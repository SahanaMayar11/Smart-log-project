import re
from datetime import datetime, timedelta

LOGON_TYPE_MAP = {
    '2': '2 (Interactive / Local Console Logon)',
    '7': '7 (Workstation Unlock)',
    '3': '3 (Network Logon / Shared Resource)',
    '10': '10 (RemoteInteractive / RDP)',
    '4': '4 (Batch Job)',
    '5': '5 (Service Logon)',
    '8': '8 (NetworkCleartext)',
    '9': '9 (NewCredentials)',
    '11': '11 (CachedInteractive)'
}

STATUS_CODE_MAP = {
    '0xc000006a': 'Bad password (username exists but password was incorrect)',
    '0xc000006d': 'Bad credentials (general authentication failure)',
    '0xc0000064': 'User does not exist',
    '0xc0000234': 'Account is currently locked out',
    '0xc0000072': 'Account is disabled',
    '0xc0000193': 'Account has expired',
    '0xc0000070': 'Workstation restriction prevented logon'
}


def parse_event_datetime(ts_str):
    """Safely parses timestamp string into a datetime object for mathematical correlation."""
    if not ts_str:
        return None
    clean = str(ts_str).replace('Z', '').replace('z', '').strip()
    for fmt in [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%d %H:%M:%S.%f',
        '%d/%b/%Y:%H:%M:%S %z',
        '%d/%b/%Y:%H:%M:%S',
        '%b %d %H:%M:%S'
    ]:
        try:
            return datetime.strptime(clean.split('+')[0].strip(), fmt)
        except Exception:
            pass
    return None


class WindowsAuthenticationCorrelator:
    """
    Evidence-based correlation engine for Windows authentication security events.
    - Groups repeated Event 4625 (Logon Failure) events by account, domain, and computer within a sliding window.
    - Accurately correlates subsequent Event 4624 (Logon) / 4801 (Unlock) only when temporal and identity evidence supports it.
    - Avoids false correlation of background services, PowerShell lifecycle, or applications (WhatsApp, Chrome).
    - Produces incident-level summaries while preserving original individual event records.
    """

    @classmethod
    def correlate_events(cls, events, time_window_seconds=300):
        if not events:
            return {'incidents': [], 'correlated_events': [], 'has_active_attack_pattern': False}

        enriched_events = []
        auth_failures = []
        auth_successes = []

        # 1. Classify and catalog authentic authentication records
        for evt in events:
            evt_copy = dict(evt)
            evt_id = int(evt_copy.get('event_id') or 0)
            action = str(evt_copy.get('action') or '')
            auth_result = evt_copy.get('auth_result')
            provider = str(evt_copy.get('provider') or '')
            channel = str(evt_copy.get('channel') or '')

            is_failed_auth = (
                evt_id == 4625
                or 'Logon Failure' in action
                or auth_result == 'failure'
                or 'Failed password' in str(evt_copy.get('message') or '')
            )
            is_success_auth = (
                evt_id in (4624, 4801)
                or 'User Logon' in action
                or 'Workstation Unlocked' in action
                or auth_result == 'success'
                or 'Accepted password' in str(evt_copy.get('message') or '')
            )

            # Mark explicit background events to avoid false correlation
            is_background = (
                'PowerShell' in provider
                or 'WLAN' in provider
                or 'Chrome' in action
                or 'WhatsApp' in action
                or evt_copy.get('event_type') in ('POWERSHELL_TELEMETRY', 'NETWORK_CONNECTIVITY')
            )

            evt_copy['is_auth_failure'] = is_failed_auth
            evt_copy['is_auth_success'] = is_success_auth
            evt_copy['is_background_telemetry'] = is_background
            evt_copy['dt'] = parse_event_datetime(evt_copy.get('timestamp') or evt_copy.get('time'))

            enriched_events.append(evt_copy)

            if is_failed_auth and evt_copy.get('dt'):
                auth_failures.append(evt_copy)
            elif is_success_auth and evt_copy.get('dt'):
                auth_successes.append(evt_copy)

        # Sort failures chronologically for temporal sequence analysis
        auth_failures.sort(key=lambda x: x['dt'])
        auth_successes.sort(key=lambda x: x['dt'])

        # 2. Correlate repeated failure clusters by (User, Computer)
        incidents = []
        clustered_failure_ids = set()

        # Group failures by target account
        user_clusters = {}
        for f in auth_failures:
            u_name = str(f.get('user') or f.get('account_name') or 'User').strip().replace('</Data', '')
            comp = str(f.get('computer') or f.get('hostname') or 'localhost').strip()
            key = (u_name.lower(), comp.lower())
            user_clusters.setdefault(key, []).append(f)

        incident_idx = 1
        for (u_lower, comp_lower), failure_list in user_clusters.items():
            if len(failure_list) == 0:
                continue

            # Sliding time window to identify bursts of failures
            i = 0
            while i < len(failure_list):
                cluster = [failure_list[i]]
                start_dt = failure_list[i]['dt']

                j = i + 1
                while j < len(failure_list):
                    diff = (failure_list[j]['dt'] - start_dt).total_seconds()
                    if 0 <= diff <= time_window_seconds:
                        cluster.append(failure_list[j])
                        j += 1
                    else:
                        break

                fail_count = len(cluster)
                # An incident is recognized when 2 or more failed attempts occur close together
                if fail_count >= 2:
                    last_failure_dt = cluster[-1]['dt']
                    u_display = cluster[0].get('user', u_lower).replace('</Data', '')
                    c_display = cluster[0].get('computer', comp_lower)
                    dom_display = str(cluster[0].get('domain') or c_display).replace('</Data', '')
                    logon_type_raw = str(cluster[0].get('logon_type') or '2')
                    logon_type_label = LOGON_TYPE_MAP.get(logon_type_raw, f"{logon_type_raw} (Interactive / Local Console)")

                    # Look for subsequent successful unlock/logon within 180 seconds after last failure
                    matching_success = None
                    for s in auth_successes:
                        s_user = str(s.get('user') or s.get('account_name') or '').strip().replace('</Data', '').lower()
                        if s_user == u_lower and s['dt'] >= start_dt:
                            s_diff = (s['dt'] - last_failure_dt).total_seconds()
                            if 0 <= s_diff <= 180:
                                matching_success = s
                                break

                    record_ids = []
                    for c in cluster:
                        if c.get('id'):
                            record_ids.append(str(c.get('id')))
                        if c.get('record_id'):
                            record_ids.append(str(c.get('record_id')))
                        if c.get('log_id'):
                            record_ids.append(str(c.get('log_id')))
                        clustered_failure_ids.add(str(c.get('id')))

                    success_ids = []
                    if matching_success:
                        if matching_success.get('id'):
                            success_ids.append(str(matching_success.get('id')))
                        if matching_success.get('record_id'):
                            success_ids.append(str(matching_success.get('record_id')))
                        if matching_success.get('log_id'):
                            success_ids.append(str(matching_success.get('log_id')))

                    if matching_success:
                        incident_desc = (
                            f"Multiple failed authentication attempts ({fail_count} attempts) were recorded for "
                            f"account '{u_display}' on {c_display} within a short period, followed by a successful logon. "
                            f"This pattern may indicate an attempted unauthorized access. Verify who performed the attempts."
                        )
                        risk_level = "High" if fail_count >= 3 else "Medium"
                        rec_action = (
                            f"Verify whether the authorized user '{u_display}' mistyped their password or if an unauthorized "
                            "individual attempted physical/console access to the locked system before the correct credentials were supplied."
                        )
                    else:
                        incident_desc = (
                            f"Multiple failed authentication attempts ({fail_count} attempts) were recorded for "
                            f"account '{u_display}' on {c_display}. No subsequent successful logon was observed."
                        )
                        risk_level = "Medium" if fail_count >= 3 else "Low"
                        rec_action = (
                            f"Review authentication logs for account '{u_display}' to ensure the account is not under active "
                            "credential guessing. Verify if account lockout policies are enforced."
                        )

                    incidents.append({
                        'incident_id': f"INC-AUTH-{incident_idx}",
                        'incident_type': 'REPEATED_AUTHENTICATION_FAILURES',
                        'title': f"Repeated Authentication Failures ({fail_count} attempts) - {u_display}",
                        'account': u_display,
                        'domain': dom_display,
                        'computer': c_display,
                        'logon_type': logon_type_label,
                        'failure_count': fail_count,
                        'first_failure_time': start_dt.strftime('%Y-%m-%d %H:%M:%S'),
                        'last_failure_time': last_failure_dt.strftime('%Y-%m-%d %H:%M:%S'),
                        'has_subsequent_success': bool(matching_success),
                        'success_time': matching_success['dt'].strftime('%Y-%m-%d %H:%M:%S') if matching_success else None,
                        'success_record_id': matching_success.get('record_id') or matching_success.get('id') if matching_success else None,
                        'success_ids': success_ids,
                        'participating_record_ids': record_ids,
                        'risk_level': risk_level,
                        'incident_description': incident_desc,
                        'recommended_action': rec_action,
                        'limitations': (
                            "Log analysis establishes that invalid credentials were submitted followed by successful authentication. "
                            "It cannot ascertain intent or definitively establish whether the attempts were made by the legitimate user "
                            "mistyping their password or another person. Verify console physical presence."
                        )
                    })
                    incident_idx += 1
                    i = j
                else:
                    i += 1

        # 3. Attach incident linkage to participating events
        for evt in enriched_events:
            evt_id_str = str(evt.get('id') or '')
            rec_id_str = str(evt.get('record_id') or '')
            log_id_str = str(evt.get('log_id') or '')
            matched_inc = next(
                (
                    inc for inc in incidents
                    if (
                        evt_id_str in inc['participating_record_ids']
                        or rec_id_str in inc['participating_record_ids']
                        or log_id_str in inc['participating_record_ids']
                        or evt_id_str in inc.get('success_ids', [])
                        or rec_id_str in inc.get('success_ids', [])
                        or log_id_str in inc.get('success_ids', [])
                    )
                ),
                None
            )
            if matched_inc:
                evt['correlation_incident_id'] = matched_inc['incident_id']
                evt['correlation_summary'] = matched_inc['incident_description']
                evt['is_correlated_incident'] = True
                evt['incident_risk_level'] = matched_inc['risk_level']
            elif evt.get('is_background_telemetry'):
                evt['is_correlated_incident'] = False
                evt['correlation_summary'] = "Routine process or network background activity during session. Not causally linked to authentication failures."
            else:
                evt['is_correlated_incident'] = False

            # Clean datetime object before JSON serialization
            evt.pop('dt', None)

        return {
            'incidents': incidents,
            'correlated_events': enriched_events,
            'has_active_attack_pattern': len(incidents) > 0
        }
