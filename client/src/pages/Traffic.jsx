import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  Search, 
  Filter, 
  ShieldAlert, 
  ShieldCheck, 
  Pause, 
  Play, 
  Eye, 
  Ban, 
  RefreshCw,
  Terminal,
  FileCode,
  X
} from 'lucide-react';
import { api } from '../services/api';
import { useSecurity } from '../context/SecurityContext';

export const Traffic = () => {
  const { blockIP, stats } = useSecurity();
  const [packets, setPackets] = useState([]);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [isLivePaused, setIsLivePaused] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchTrafficPackets = async () => {
    if (isLivePaused) return;
    try {
      const res = await api.getTraffic(filter, search, 100);
      if (res.success) {
        setPackets(res.data);
      }
    } catch (err) {
      console.warn('Error fetching traffic:', err);
    }
  };

  useEffect(() => {
    fetchTrafficPackets();
    const interval = setInterval(fetchTrafficPackets, 1000);
    return () => clearInterval(interval);
  }, [filter, search, isLivePaused]);

  const handleQuickBlock = (ip) => {
    blockIP(ip, 'Blocked directly from Traffic Monitor inspection');
  };

  const statusBadge = (status) => {
    switch (status) {
      case 'NORMAL':
        return <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">NORMAL</span>;
      case 'SUSPICIOUS':
        return <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 animate-pulse">SUSPICIOUS</span>;
      case 'BLOCKED':
        return <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-slate-800 text-cyan-300 border border-cyan-500/40">BLOCKED</span>;
      case 'RATE_LIMITED':
        return <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/10 text-amber-300 border border-amber-500/30">THROTTLED</span>;
      default:
        return <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-slate-800 text-slate-300">{status}</span>;
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Header & Control Bar */}
      <div className="cyber-panel p-5 rounded-xl border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-mono font-bold text-white flex items-center gap-2">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <span>REAL-TIME PACKET TELEMETRY FEED</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Inspecting live synthetic packets flowing into Gateway (192.168.1.1) • Showing {packets.length} samples
          </p>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <button
            onClick={() => setIsLivePaused(!isLivePaused)}
            className={`px-3 py-1.5 rounded-lg border font-mono text-xs flex items-center gap-1.5 transition-all ${
              isLivePaused 
                ? 'bg-amber-950/50 text-amber-300 border-amber-500/40' 
                : 'bg-slate-900 text-slate-300 border-slate-700 hover:text-white'
            }`}
          >
            {isLivePaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isLivePaused ? 'RESUME STREAM' : 'PAUSE STREAM'}</span>
          </button>

          <button
            onClick={fetchTrafficPackets}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 hover:text-cyan-400 transition-all"
            title="Force refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Filter and Search Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 font-mono text-xs">
        
        {/* Search input */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search source IP, protocol, flags, URI..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900/90 border border-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-all"
          />
        </div>

        {/* Filter tabs */}
        <div className="flex items-center gap-1 p-1 bg-slate-950/80 border border-slate-800 rounded-lg overflow-x-auto">
          {['all', 'normal', 'suspicious', 'blocked', 'rate_limited'].map((tab) => (
            <button
              key={tab}
              onClick={() => setFilter(tab)}
              className={`px-3 py-1.5 rounded-md uppercase text-[11px] font-semibold transition-all ${
                filter === tab 
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              {tab.replace('_', ' ')}
            </button>
          ))}
        </div>

      </div>

      {/* Traffic Packet Table */}
      <div className="cyber-panel rounded-xl border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-950/90 border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Destination</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">Requests</th>
                <th className="py-3 px-4">Volume</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {packets.length === 0 ? (
                <tr>
                  <td colSpan="9" className="py-12 text-center text-slate-500">
                    No packet records match the current filter or search criteria.
                  </td>
                </tr>
              ) : (
                packets.map((pkt) => (
                  <tr 
                    key={pkt.id} 
                    className="hover:bg-slate-800/40 transition-colors group"
                  >
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                      {new Date(pkt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-4 font-bold text-slate-200 whitespace-nowrap">
                      {pkt.sourceIP}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                      {pkt.destIP}:{pkt.port}
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <span className="text-cyan-400 font-semibold">{pkt.protocol}</span>
                      <span className="text-slate-500 text-[10px] ml-1">({pkt.flags})</span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-300 font-bold whitespace-nowrap">
                      {pkt.requestCount}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                      {pkt.packetVolumeKB} KB
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <span className={`text-[11px] font-semibold ${
                        pkt.attackType !== 'None' ? 'text-rose-400' : 'text-slate-400'
                      }`}>
                        {pkt.attackType}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      {statusBadge(pkt.status)}
                    </td>
                    <td className="py-2.5 px-4 text-right whitespace-nowrap space-x-2">
                      <button
                        onClick={() => setSelectedPacket(pkt)}
                        className="p-1 rounded bg-slate-800 text-slate-300 hover:text-cyan-400 hover:bg-slate-700 transition-all"
                        title="Inspect Packet Headers"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      {pkt.status !== 'BLOCKED' && (
                        <button
                          onClick={() => handleQuickBlock(pkt.sourceIP)}
                          className="p-1 rounded bg-slate-800 text-rose-400 hover:bg-rose-950/60 hover:border-rose-500/50 transition-all"
                          title="Block Source IP"
                        >
                          <Ban className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Packet Inspector Modal */}
      {selectedPacket && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
          <div className="cyber-panel p-6 rounded-xl border border-cyan-500/40 bg-[#0C1220] max-w-2xl w-full shadow-2xl relative font-mono text-xs">
            
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-bold text-white">DEEP PACKET INSPECTOR</span>
                <span className="text-slate-500">[{selectedPacket.id}]</span>
              </div>
              <button 
                onClick={() => setSelectedPacket(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="py-4 space-y-4">
              
              {/* Header Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                <div>
                  <span className="text-slate-500 text-[10px] uppercase">Source IP</span>
                  <p className="font-bold text-cyan-300">{selectedPacket.sourceIP}</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase">Destination</span>
                  <p className="font-bold text-white">{selectedPacket.destIP}:{selectedPacket.port}</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase">Protocol & Flags</span>
                  <p className="font-bold text-amber-400">{selectedPacket.protocol} [{selectedPacket.flags}]</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase">Request Rate</span>
                  <p className="font-bold text-white">{selectedPacket.requestCount} req/burst</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase">Payload Volume</span>
                  <p className="font-bold text-white">{selectedPacket.packetVolumeKB} KB</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase">Firewall Action</span>
                  <p className="font-bold text-emerald-400">{selectedPacket.status}</p>
                </div>
              </div>

              {/* L7 Details */}
              <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 space-y-2">
                <div>
                  <span className="text-slate-500 text-[10px] uppercase">Target URI / Resource:</span>
                  <p className="text-slate-200">{selectedPacket.uri}</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase">User-Agent / Signature:</span>
                  <p className="text-slate-300 text-[11px]">{selectedPacket.userAgent}</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase">Mitigation Evaluation:</span>
                  <p className="text-cyan-400 font-semibold">{selectedPacket.mitigationReason || 'Permitted by security baseline.'}</p>
                </div>
              </div>

              {/* Synthetic Hex Dump preview */}
              <div>
                <span className="text-slate-500 text-[10px] uppercase block mb-1">Simulated Packet Byte Dump:</span>
                <pre className="p-3 rounded-lg bg-black/60 border border-slate-800 text-[10px] text-emerald-400 overflow-x-auto leading-relaxed">
{`0000  00 1a 2b 3c 4d 5e 00 50  56 c0 00 08 08 00 45 00  ..+<m^.PV.....E.
0010  00 3c 1a 2b 40 00 40 06  b2 85 c0 a8 01 65 c0 a8  .<.+@.@......e..
0020  01 01 c0 01 00 50 00 00  00 00 00 00 00 00 a0 02  .....P..........
0030  72 10 7a 48 00 00 02 04  05 b4 04 02 08 0a 01 23  r.zH...........#
Payload Signature: [Attack-Vector: ${selectedPacket.attackType}]`}
                </pre>
              </div>

            </div>

            {/* Modal Actions */}
            <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
              <button
                onClick={() => {
                  handleQuickBlock(selectedPacket.sourceIP);
                  setSelectedPacket(null);
                }}
                className="px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold flex items-center gap-1.5 transition-all"
              >
                <Ban className="w-3.5 h-3.5" />
                <span>Block {selectedPacket.sourceIP}</span>
              </button>

              <button
                onClick={() => setSelectedPacket(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-all"
              >
                Close Inspector
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};
