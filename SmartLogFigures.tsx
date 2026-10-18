import React from 'react';

/**
 * SmartLogFigures.tsx
 * =============================================================================
 * Publication-Grade Academic Figures for Smart-Log IEEE Research Paper:
 * 1. Figure 1: System Architecture Diagram (fig_arch.png)
 * 2. Figure 2: Empirical ROC Curve Comparison (fig_roc.png)
 * 3. Figure 3: TreeSHAP Feature Attribution Waterfall (fig_shap.png)
 * =============================================================================
 */

export const SmartLogArchitectureFigure: React.FC = () => {
  return (
    <div className="w-full max-w-5xl bg-white p-6 border border-slate-300 rounded font-sans text-slate-900">
      <div className="text-center font-bold text-lg mb-4 text-slate-800">
        Smart-Log: End-to-End System Architecture
      </div>

      {/* Layer 1: Ingestion & Parsing */}
      <div className="mb-4 p-4 border border-dashed border-slate-300 rounded bg-slate-50">
        <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
          Layer 1: Ingestion & Parsing
        </span>
        <div className="mt-2 flex justify-center">
          <div className="border border-slate-800 bg-white px-6 py-2 rounded shadow-sm text-center">
            <div className="font-bold text-sm">SERVER SYSTEM LOGS</div>
            <div className="text-xs text-slate-600">Raw Syslog Streams / OS Telemetry</div>
          </div>
        </div>
      </div>

      {/* Layer 2: Preprocessing & Feature Engineering */}
      <div className="mb-4 p-4 border border-dashed border-slate-300 rounded bg-slate-50">
        <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
          Layer 2: Preprocessing & Feature Engineering
        </span>
        <div className="mt-2 grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2 border border-slate-800 bg-white p-3 rounded text-center">
            <div className="font-bold text-sm">LOG INGESTION, CLEANING & PREPROCESSING</div>
            <div className="text-xs text-slate-600 mt-1">
              Regex Parser: ⟨t, h, s, ℓ, m⟩ | Median Imputation | Extreme Value Bounding
            </div>
            <div className="font-bold text-sm mt-3">BEHAVIORAL FEATURE ENGINEERING</div>
            <div className="text-xs text-slate-600">
              Temporal Sliding Window (W=5) | 8-Dimensional Feature Space
            </div>
          </div>
          <div className="border border-amber-600 bg-amber-50 p-3 rounded text-xs text-amber-900 font-mono">
            <div className="font-bold text-amber-800 mb-1">8 Canonical Features:</div>
            <div>• f₁: event_frequency</div>
            <div>• f₂: sequence_length</div>
            <div>• f₃: error_count</div>
            <div>• f₄: error_pattern</div>
            <div>• f₅: login_attempts</div>
            <div>• f₆: failed_login_attempts</div>
            <div>• f₇: warning_count</div>
            <div>• f₈: unknown_events</div>
          </div>
        </div>
      </div>

      {/* Layer 3: Detection & Validation */}
      <div className="mb-4 p-4 border border-dashed border-slate-300 rounded bg-slate-50">
        <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
          Layer 3: Detection & Validation
        </span>
        <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="border-2 border-sky-600 bg-sky-50 p-3 rounded text-center">
            <div className="font-bold text-sm text-sky-900">ISOLATION FOREST (PRIMARY DETECTOR)</div>
            <div className="text-xs text-sky-700 mt-1">
              Unsupervised Tree Isolation (N_t=100) | Decision Score S_IF ≥ 0.50
            </div>
          </div>
          <div className="border border-slate-600 bg-slate-100 p-3 rounded text-center">
            <div className="font-bold text-sm text-slate-800">ONE-CLASS SVM (SECONDARY VALIDATOR)</div>
            <div className="text-xs text-slate-600 mt-1">
              Nonlinear RBF Kernel (ν) | Geometric Hyperplane Boundary
            </div>
          </div>
        </div>

        <div className="mt-3 border border-slate-800 bg-white p-3 rounded text-center">
          <div className="font-bold text-sm text-slate-900">CONSENSUS DECISION & FOUR-STATE TRIAGE</div>
          <div className="text-xs text-slate-700 mt-1 grid grid-cols-2 md:grid-cols-4 gap-2">
            <span className="bg-emerald-50 text-emerald-800 p-1 rounded border border-emerald-300">
              Consensus Normal (IF=0, SVM=0)
            </span>
            <span className="bg-rose-50 text-rose-800 p-1 rounded border border-rose-300 font-semibold">
              Consensus Anomaly (IF=1, SVM=1)
            </span>
            <span className="bg-amber-50 text-amber-800 p-1 rounded border border-amber-300">
              Disagreement: IF Only
            </span>
            <span className="bg-slate-50 text-slate-800 p-1 rounded border border-slate-300">
              Disagreement: SVM Only
            </span>
          </div>
        </div>
      </div>

      {/* Layer 4: Explainability & Alerting */}
      <div className="p-4 border border-dashed border-slate-300 rounded bg-slate-50">
        <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
          Layer 4: Explainability & Alerting
        </span>
        <div className="mt-2 grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2 border border-indigo-700 bg-indigo-50 p-3 rounded text-center">
            <div className="font-bold text-sm text-indigo-900">TreeSHAP FEATURE ATTRIBUTION</div>
            <div className="text-xs text-indigo-700 mt-1">
              Additive Shapley Attributions (Primary IF) | Standard-Score Fallback Heuristic
            </div>
          </div>
          <div className="border border-red-600 bg-red-50 p-3 rounded text-center">
            <div className="font-bold text-sm text-red-900">GENERATED ALERTS</div>
            <div className="text-xs text-red-700 mt-1">
              Severity Bands (Normal/Low/Med/High/Crit) + Diagnostic Context
            </div>
          </div>
        </div>
      </div>

      {/* References Section */}
      <div className="mt-6 p-4 border-t border-slate-300">
        <div className="font-bold text-sm text-slate-800 mb-3">References</div>
        <ol className="text-xs text-slate-700 space-y-2 list-none p-0 m-0">
          <li>
            <span className="font-semibold">[1].</span> Anomaly Identification in Cyber Logs Through Machine Learning Techniques – Ram Dwivedi, Nitesh Gupta, Anurag Shrivastava<br />
            <span className="text-slate-500">Link: </span><a href="https://doi.org/10.55083/irjeas.2025.v13i04002" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://doi.org/10.55083/irjeas.2025.v13i04002</a>
          </li>
          <li>
            <span className="font-semibold">[2].</span> Anomaly Detection of Denial-of-Service Network Traffic Attacks using Autoencoders and Isolation Forest – Nur-Adib Maspo, Muhammad Thaqif Ghulam Hussain, Aman Shafeeq Lone, Zainab Senan Mahmod Attar Bashi<br />
            <span className="text-slate-500">Link: </span><a href="https://journals.iium.edu.my/kict/index.php/IJPCC/article/view/680" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://journals.iium.edu.my/kict/index.php/IJPCC/article/view/680</a>
          </li>
          <li>
            <span className="font-semibold">[3].</span> Unsupervised Log Message Anomaly Detection – Amir Farzad, T. Aaron Gulliver<br />
            <span className="text-slate-500">Link: </span><a href="https://www.sciencedirect.com/science/article/pii/S2405959520300643" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://www.sciencedirect.com/science/article/pii/S2405959520300643</a>
          </li>
          <li>
            <span className="font-semibold">[4].</span> Log Anomaly Detection via Meta-Learning and Prototypical Networks – Krishna Sharma, Vivek Yelleti<br />
            <span className="text-slate-500">Link: </span><a href="https://arxiv.org/abs/2601.14336" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://arxiv.org/abs/2601.14336</a>
          </li>
          <li>
            <span className="font-semibold">[5].</span> LLM-Enhanced Log Anomaly Detection: A Comprehensive Benchmark – Disha Patel<br />
            <span className="text-slate-500">Link: </span><a href="https://arxiv.org/abs/2604.12218" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://arxiv.org/abs/2604.12218</a>
          </li>
          <li>
            <span className="font-semibold">[6].</span> Deep Learning Advancements in Anomaly Detection: A Comprehensive Survey – Haoqi Huang, Ping Wang, Jianhua Pei, Jiacheng Wang, Shahen Alexanian, Dusit Niyato<br />
            <span className="text-slate-500">Link: </span><a href="https://arxiv.org/abs/2503.13195" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://arxiv.org/abs/2503.13195</a>
          </li>
          <li>
            <span className="font-semibold">[7].</span> A Comparative Study of Log-Based Anomaly Detection Methods in Real-World System Logs – Nadira Anjum Nipa, Nizar Bouguila, Zachary Patterson<br />
            <span className="text-slate-500">Link: </span><a href="https://www.scitepress.org/publishedPapers/2025/133670/pdf/index.html" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://www.scitepress.org/publishedPapers/2025/133670/pdf/index.html</a>
          </li>
          <li>
            <span className="font-semibold">[8].</span> Log-Based Anomaly Detection: Comparative Study of Real-World System Logs using Machine Learning and Deep Learning Approaches – Nadira Anjum Nipa, Nizar Bouguila, Zachary Patterson<br />
            <span className="text-slate-500">Link: </span><a href="https://www.scitepress.org/Papers/2025/133670/133670.pdf" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://www.scitepress.org/Papers/2025/133670/133670.pdf</a>
          </li>
          <li>
            <span className="font-semibold">[9].</span> System Log Anomaly Detection based on Contrastive Learning and Retrieval-Augmented – Weian Li, Yang Wu, Wei Huang, Faheng Zhou, Weihua Ou, Hongbing Wang, Lunzhi Deng<br />
            <span className="text-slate-500">Link: </span><a href="https://www.nature.com/articles/s41598-025-22208-7" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://www.nature.com/articles/s41598-025-22208-7</a>
          </li>
          <li>
            <span className="font-semibold">[10].</span> Improving Anomaly Detection in the HDFS Dataset – Mohammed Bekkouche, Sidi Mohammed Benslimane<br />
            <span className="text-slate-500">Link: </span><a href="https://mdbekkouche.github.io/" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://mdbekkouche.github.io/</a>
          </li>
          <li>
            <span className="font-semibold">[11].</span> Improving Anomaly Detection in the HDFS Dataset with Novel Machine Learning Models and Techniques – Mohammed Bekkouche, Sidi Mohammed Benslimane<br />
            <span className="text-slate-500">Link: </span><a href="https://mdbekkouche.github.io/" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://mdbekkouche.github.io/</a>
          </li>
          <li>
            <span className="font-semibold">[12].</span> Log2Graphs: An Unsupervised Framework for Log Anomaly Detection with Efficient Feature Extraction – Cheng Wang, Zeyan Li, Minghua Ma, Pengfei Chen<br />
            <span className="text-slate-500">Link: </span><a href="https://arxiv.org/abs/2307.00527" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://arxiv.org/abs/2307.00527</a>
          </li>
          <li>
            <span className="font-semibold">[13].</span> Deep Learning-based Anomaly Detection and Log Analysis for Computer Networks – Shuzhan Wang, Ruxue Jiang, Zhaoqi Wang, Yan Zhou<br />
            <span className="text-slate-500">Link: </span><a href="https://arxiv.org/abs/2407.05639" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://arxiv.org/abs/2407.05639</a>
          </li>
          <li>
            <span className="font-semibold">[14].</span> Reducing Events to Augment Log-based Anomaly Detection Models: An Empirical Study – Lingzhe Zhang, Tong Jia, Kangjin Wang, Mengxi Jia, Yang Yong, Ying Li<br />
            <span className="text-slate-500">Link: </span><a href="https://arxiv.org/abs/2409.04834" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://arxiv.org/abs/2409.04834</a>
          </li>
          <li>
            <span className="font-semibold">[15].</span> Online Isolation Forest – Filippo Leveni, Guilherme Weigert Cassales, Bernhard Pfahringer, Albert Bifet, Giacomo Boracchi<br />
            <span className="text-slate-500">Link: </span><a href="https://arxiv.org/abs/2505.09593" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://arxiv.org/abs/2505.09593</a>
          </li>
          <li>
            <span className="font-semibold">[16].</span> Deep Learning-based System Log Analysis for Anomaly Detection – Zhuangbin Chen, Jinyang Liu, Wenwei Gu, Yuxin Su, Michael R. Lyu<br />
            <span className="text-slate-500">Link: </span><a href="https://arxiv.org/abs/2107.05908" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://arxiv.org/abs/2107.05908</a>
          </li>
          <li>
            <span className="font-semibold">[17].</span> Deep learning for anomaly detection in log data: A survey – Max Landauer, Sebastian Onder, Florian Skopik, Markus Wurzenberger<br />
            <span className="text-slate-500">Link: </span><a href="https://www.researchgate.net/publication/371216048_Deep_learning_for_anomaly_detection_in_log_data_A_survey" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://www.researchgate.net/publication/371216048_Deep_learning_for_anomaly_detection_in_log_data_A_survey</a>
          </li>
          <li>
            <span className="font-semibold">[18].</span> DeepLog: Anomaly Detection and Diagnosis from System Logs through Deep Learning – Min Du, Feifei Li, Guineng Zheng, Vivek Srikumar<br />
            <span className="text-slate-500">Link: </span><a href="https://dl.acm.org/doi/10.1145/3133956.3134015" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://dl.acm.org/doi/10.1145/3133956.3134015</a>
          </li>
          <li>
            <span className="font-semibold">[19].</span> LogAnomaly: Unsupervised Detection of Sequential and Quantitative Anomalies in Unstructured Logs – Qiang Huang, Jian-Guang Lou, Yi Wang, Qingwei Lin, Dongmei Zhang<br />
            <span className="text-slate-500">Link: </span><a href="https://www.ijcai.org/proceedings/2019/0658.pdf" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://www.ijcai.org/proceedings/2019/0658.pdf</a>
          </li>
          <li>
            <span className="font-semibold">[20].</span> LogBERT: Log Anomaly Detection via BERT – Yifei Yuan, Yudong Li, Sheng Wen<br />
            <span className="text-slate-500">Link: </span><a href="https://arxiv.org/abs/2103.04475" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://arxiv.org/abs/2103.04475</a>
          </li>
          <li>
            <span className="font-semibold">[21].</span> A Deep Learning Approach for Network Intrusion Detection System – A. Javaid, Q. Niyaz, W. Sun, M. Alam<br />
            <span className="text-slate-500">Link: </span><a href="https://doi.org/10.4108/eai.3-12-2015.2262516" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://doi.org/10.4108/eai.3-12-2015.2262516</a>
          </li>
          <li>
            <span className="font-semibold">[22].</span> Anomaly Detection in Cybersecurity Logs using Deep Autoencoders – T. Nguyen, M. Aiello<br />
            <span className="text-slate-500">Link: </span><a href="https://doi.org/10.1016/j.future.2020.09.018" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://doi.org/10.1016/j.future.2020.09.018</a>
          </li>
          <li>
            <span className="font-semibold">[23].</span> Anomaly Detection using Isolation Forest and K-Means Clustering – A. Sharma, S. Mukhopadhyay<br />
            <span className="text-slate-500">Link: </span><a href="https://ieeexplore.ieee.org/document/9225482" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://ieeexplore.ieee.org/document/9225482</a>
          </li>
          <li>
            <span className="font-semibold">[24].</span> Anomaly Detection for Cyber Security using LSTM and GRU – P. Goyal, A. Bansal, D. Tomar<br />
            <span className="text-slate-500">Link: </span><a href="https://ieeexplore.ieee.org/document/10192808" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://ieeexplore.ieee.org/document/10192808</a>
          </li>
          <li>
            <span className="font-semibold">[25].</span> A Hybrid Model for Log Anomaly Detection based on CNN and Attention Mechanism – H. Miao, J. Ding, L. Zhang<br />
            <span className="text-slate-500">Link: </span><a href="https://ieeexplore.ieee.org/document/10004843" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://ieeexplore.ieee.org/document/10004843</a>
          </li>
        </ol>
      </div>
    </div>
  );
};

export default SmartLogArchitectureFigure;
