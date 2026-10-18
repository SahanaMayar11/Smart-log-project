import React from 'react';
import socBg from '../../assets/soc_bg.jpg';
import cyberMesh from '../../assets/cyber_mesh.jpg';

const CyberBackground = () => {
  // Static node coordinates for network mesh overlay
  const nodes = [
    { x: 10, y: 15, r: 3 },
    { x: 25, y: 35, r: 4 },
    { x: 45, y: 20, r: 3 },
    { x: 60, y: 40, r: 5 },
    { x: 75, y: 15, r: 3 },
    { x: 90, y: 30, r: 4 },
    { x: 15, y: 70, r: 4 },
    { x: 35, y: 85, r: 3 },
    { x: 55, y: 65, r: 5 },
    { x: 70, y: 80, r: 3 },
    { x: 85, y: 75, r: 4 },
  ];

  const connections = [
    [0, 1], [1, 2], [2, 3], [3, 4], [4, 5],
    [0, 6], [1, 6], [2, 8], [3, 8], [3, 9], [4, 10], [5, 10],
    [6, 7], [7, 8], [8, 9], [9, 10]
  ];

  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden bg-[#050816]">
      {/* 1. Smooth Dark Overlaid Premium Background Image */}
      <img
        src={socBg}
        alt="SOC Background"
        className="absolute inset-0 w-full h-full object-cover opacity-20 filter brightness-75 contrast-125 mix-blend-luminosity"
      />

      {/* 2. Secondary Blended Mesh Overlay */}
      <img
        src={cyberMesh}
        alt="Cyber Mesh"
        className="absolute inset-0 w-full h-full object-cover opacity-10 mix-blend-screen"
      />

      {/* 3. Dark Navy Gradient Shield Overlay (Ensures text contrast & readability) */}
      <div className="absolute inset-0 bg-gradient-to-b from-[#050816]/85 via-[#050816]/65 to-[#050816]/90" />

      {/* 4. Ambient Cyan & Purple Radial Glow Spheres */}
      <div className="absolute -top-40 left-1/4 w-[750px] h-[750px] bg-cyan-500/10 rounded-full blur-[150px]" />
      <div className="absolute top-1/3 -right-40 w-[650px] h-[650px] bg-purple-600/10 rounded-full blur-[150px]" />
      <div className="absolute -bottom-40 left-1/3 w-[750px] h-[750px] bg-blue-600/08 rounded-full blur-[160px]" />

      {/* 5. Static Cyber Grid */}
      <div className="absolute inset-0 cyber-grid opacity-20" />

      {/* 6. Static SVG Circuit Board & Network Node Mesh */}
      <svg className="absolute inset-0 w-full h-full opacity-20" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="cyan-gradient-static" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#22D3EE" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#3B82F6" stopOpacity="0.1" />
          </linearGradient>
        </defs>

        {/* Network Connection Lines */}
        {connections.map(([startIdx, endIdx], idx) => (
          <line
            key={idx}
            x1={`${nodes[startIdx].x}%`}
            y1={`${nodes[startIdx].y}%`}
            x2={`${nodes[endIdx].x}%`}
            y2={`${nodes[endIdx].y}%`}
            stroke="url(#cyan-gradient-static)"
            strokeWidth="1"
            strokeDasharray="4 4"
          />
        ))}

        {/* Network Nodes */}
        {nodes.map((node, idx) => (
          <g key={idx}>
            <circle
              cx={`${node.x}%`}
              cy={`${node.y}%`}
              r={node.r + 2}
              fill="rgba(34, 211, 238, 0.12)"
            />
            <circle
              cx={`${node.x}%`}
              cy={`${node.y}%`}
              r={node.r}
              fill="#22D3EE"
            />
          </g>
        ))}
      </svg>
    </div>
  );
};

export default CyberBackground;
