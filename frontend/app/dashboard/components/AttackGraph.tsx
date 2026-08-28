'use client';

import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { ZoomIn, ZoomOut, RotateCcw, Info, ShieldAlert, Globe, Server, Hash } from 'lucide-react';

interface Node extends d3.SimulationNodeDatum {
  id: string;
  type: string;
  label: string;
  color: string;
  size: number;
  data?: {
    subject?: string;
    from?: string;
    region?: string;
    severity?: string;
    risk_score?: number;
    value?: string;
  };
}

interface Edge extends d3.SimulationLinkDatum<Node> {
  source: string | Node;
  target: string | Node;
  relationship?: string;
}

interface AttackGraphProps {
  data: {
    nodes: Node[];
    edges: Edge[];
    total_nodes?: number;
    total_edges?: number;
  };
  onSelectNode?: (node: Node) => void;
}

export default function AttackGraph({ data, onSelectNode }: AttackGraphProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);

  useEffect(() => {
    if (!svgRef.current || !data || !data.nodes || data.nodes.length === 0) return;

    const container = containerRef.current;
    const width = container ? container.clientWidth : 800;
    const height = 550;

    // Clear previous SVG contents
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg
      .attr('width', '100%')
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('class', 'overflow-hidden rounded-2xl');

    // Create container group for zoom/pan
    const g = svg.append('g');

    // Setup zoom behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    // Deep clone nodes and edges to avoid D3 mutation issues
    const nodes: Node[] = data.nodes.map(d => ({ ...d }));
    const edges: Edge[] = data.edges.map(d => ({ ...d }));

    // Force simulation
    const simulation = d3.forceSimulation<Node>(nodes)
      .force('link', d3.forceLink<Node, Edge>(edges).id(d => d.id).distance(90))
      .force('charge', d3.forceManyBody().strength(-240))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => (d as Node).size * 2 + 5));

    // Render Edges
    const link = g.append('g')
      .attr('stroke', '#334155')
      .attr('stroke-opacity', 0.6)
      .selectAll('line')
      .data(edges)
      .join('line')
      .attr('stroke-width', 1.5)
      .attr('stroke-dasharray', d => d.relationship === 'campaign' ? '4,4' : 'none');

    // Render Nodes (Groups)
    const node = g.append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .attr('class', 'cursor-pointer group')
      .call(
        d3.drag<SVGGElement, Node>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      );

    // Node Outer Glow Halo
    node.append('circle')
      .attr('r', d => d.size + 4)
      .attr('fill', d => d.color)
      .attr('opacity', 0.15)
      .attr('class', 'transition-all duration-300 group-hover:opacity-40 group-hover:scale-125');

    // Main Node Circle
    node.append('circle')
      .attr('r', d => d.size)
      .attr('fill', d => d.color)
      .attr('stroke', '#0F172A')
      .attr('stroke-width', 2)
      .attr('class', 'transition-transform duration-200');

    // Node Label
    node.append('text')
      .text(d => d.label)
      .attr('x', d => d.size + 6)
      .attr('y', 4)
      .attr('fill', '#94A3B8')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace')
      .attr('pointer-events', 'none')
      .attr('class', 'select-none group-hover:fill-cyan-300 transition-colors');

    // Click handler for node selection
    node.on('click', (event, d) => {
      event.stopPropagation();
      setSelectedNode(d);
      if (onSelectNode) onSelectNode(d);
    });

    // Background click to deselect
    svg.on('click', () => {
      setSelectedNode(null);
    });

    // Simulation Tick Updates
    simulation.on('tick', () => {
      link
        .attr('x1', d => (d.source as Node).x || 0)
        .attr('y1', d => (d.source as Node).y || 0)
        .attr('x2', d => (d.target as Node).x || 0)
        .attr('y2', d => (d.target as Node).y || 0);

      node.attr('transform', d => `translate(${d.x || 0},${d.y || 0})`);
    });

    return () => {
      simulation.stop();
    };
  }, [data]);

  return (
    <div ref={containerRef} className="relative w-full glass-panel rounded-3xl p-4 border border-slate-800">
      {/* Header with Legend */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-3 px-2">
        <div className="flex items-center space-x-2">
          <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
          <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
            Live Threat Correlation Attack Graph (NetworkX)
          </h3>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-400 bg-slate-950/60 px-3 py-1.5 rounded-xl border border-slate-800/80">
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#38BDF8]" />
            <span>Email</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#34D399]" />
            <span>Domain</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#FBBF24]" />
            <span>IP / Subnet</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#A78BFA]" />
            <span>Msg-ID Domain</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#F87171]" />
            <span>Return-Path</span>
          </div>
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="relative bg-slate-950/70 rounded-2xl border border-slate-800/60 overflow-hidden">
        <svg ref={svgRef} className="w-full" style={{ height: '520px' }} />

        {/* Node Inspection Modal / Popover */}
        {selectedNode && (
          <div className="absolute top-4 right-4 max-w-sm w-full glass-panel-glow p-5 rounded-2xl border border-cyan-500/40 text-slate-200 shadow-2xl z-20 animate-in fade-in slide-in-from-top-2 duration-200">
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <span
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: selectedNode.color }}
                />
                <span className="text-xs font-mono font-bold uppercase text-cyan-400">
                  {selectedNode.type} Node
                </span>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-white text-xs px-2 py-0.5 rounded bg-slate-800/80"
              >
                ✕
              </button>
            </div>

            <div className="mt-3 text-sm font-semibold text-white break-words">
              {selectedNode.label}
            </div>

            {selectedNode.data && (
              <div className="mt-3 space-y-1.5 text-xs text-slate-300 font-mono border-t border-slate-800 pt-3">
                {selectedNode.data.from && (
                  <div>
                    <span className="text-slate-500">From: </span>
                    <span className="text-cyan-300">{selectedNode.data.from}</span>
                  </div>
                )}
                {selectedNode.data.region && (
                  <div>
                    <span className="text-slate-500">Region: </span>
                    <span className="text-purple-300">{selectedNode.data.region}</span>
                  </div>
                )}
                {selectedNode.data.severity && (
                  <div>
                    <span className="text-slate-500">Severity: </span>
                    <span
                      className={
                        selectedNode.data.severity === 'CRITICAL'
                          ? 'text-rose-400 font-bold'
                          : selectedNode.data.severity === 'HIGH'
                          ? 'text-amber-400 font-bold'
                          : 'text-emerald-400 font-bold'
                      }
                    >
                      {selectedNode.data.severity} ({selectedNode.data.risk_score}/100)
                    </span>
                  </div>
                )}
                {selectedNode.data.value && (
                  <div>
                    <span className="text-slate-500">Indicator: </span>
                    <span className="text-slate-200">{selectedNode.data.value}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Empty state hint */}
        {(!data.nodes || data.nodes.length === 0) && (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 text-sm">
            <Info className="w-8 h-8 mb-2 text-slate-600 animate-pulse" />
            <span>Upload or select .eml files to correlate threat campaigns</span>
          </div>
        )}
      </div>
    </div>
  );
}
