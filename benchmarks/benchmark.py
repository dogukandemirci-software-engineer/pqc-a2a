from __future__ import annotations
import csv, json, statistics, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / 'src'))
from pqc_a2a import AgentIdentity, ReplayCache, open_envelope, seal


def run(n: int = 20):
    sender, receiver = AgentIdentity('agent-a'), AgentIdentity('agent-b')
    payloads = [b'x' * s for s in (256, 4096, 16384)]
    rows=[]
    for payload in payloads:
        enc=[]; dec=[]; sizes=[]
        for i in range(n):
            body={'type':'task.result','seq':i,'payload':payload.decode('ascii')}
            t=time.perf_counter_ns(); env=seal(sender, receiver, body); enc.append((time.perf_counter_ns()-t)/1e6); sizes.append(len(json.dumps(env)))
            t=time.perf_counter_ns(); got=open_envelope(receiver, sender, env, ReplayCache()); dec.append((time.perf_counter_ns()-t)/1e6)
            assert got == body
        rows.append({'payload_bytes':len(payload),'encrypt_ms_median':statistics.median(enc),'decrypt_ms_median':statistics.median(dec),'envelope_bytes':statistics.median(sizes),'roundtrip_ms_median':statistics.median([a+b for a,b in zip(enc,dec)])})
    out=Path(__file__).parent/'results.csv'; out.parent.mkdir(exist_ok=True)
    with out.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys(), lineterminator='\n')
        writer.writeheader(); writer.writerows(rows)
    make_plot(rows, Path(__file__).parent/'benchmark.png')
    print(json.dumps({'samples':n,'rows':rows}, indent=2))


def make_plot(rows, path):
    import matplotlib.pyplot as plt
    plt.style.use('seaborn-v0_8-whitegrid')
    x=[r['payload_bytes'] for r in rows]
    fig, ax=plt.subplots(1,2,figsize=(11,4.5))
    ax[0].plot(x,[r['encrypt_ms_median'] for r in rows],marker='o',label='Seal')
    ax[0].plot(x,[r['decrypt_ms_median'] for r in rows],marker='o',label='Open')
    ax[0].set_xscale('log',base=2); ax[0].set_xlabel('Payload (bytes)'); ax[0].set_ylabel('Median latency (ms)'); ax[0].set_title('Hybrid PQC A2A latency'); ax[0].legend()
    ax[1].plot(x,[r['envelope_bytes'] for r in rows],marker='o',color='#c44e52')
    ax[1].set_xscale('log',base=2); ax[1].set_xlabel('Payload (bytes)'); ax[1].set_ylabel('Envelope (bytes)'); ax[1].set_title('Wire overhead')
    fig.tight_layout(); fig.savefig(path,dpi=180); plt.close(fig)

if __name__=='__main__': run(int(sys.argv[1]) if len(sys.argv)>1 else 20)
