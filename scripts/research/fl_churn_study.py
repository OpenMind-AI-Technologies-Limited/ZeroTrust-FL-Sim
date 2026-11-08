"""Synthetic non-IID FL quorum/churn study; does not exercise Go coordinator or network."""
import argparse
import csv
import hashlib
import json
import math
import random
import statistics
from pathlib import Path

SCENARIOS=("control","revoked_no_replacement","revoked_with_replacement")
QUORUM=3
def sigmoid(z): return 1/(1+math.exp(-max(-30,min(30,z))))

def samples(seed):
 r=random.Random(seed);data=[]
 for y,c in ((0,(-1.,-.8)),(1,(1.,.8))):
  data.extend((r.gauss(c[0],1.),r.gauss(c[1],1.),y) for _ in range(120))
 r.shuffle(data)
 return data[:180],data[180:]

def partitions(train,seed,alpha):
 r=random.Random(seed);groups={k:[] for k in range(4)}
 for y in (0,1):
  examples=[e for e in train if e[2]==y];r.shuffle(examples)
  weights=[r.gammavariate(alpha,1) for _ in range(4)]
  for e in examples:
   v=r.random()*sum(weights);j=0
   while j<3 and v>weights[j]: v-=weights[j];j+=1
   groups[j].append(e)
 return groups if all(groups.values()) else None

def evaluate(weights,data):
 probs=[sigmoid(weights[0]*x+weights[1]*y+weights[2]) for x,y,_ in data]
 accuracy=sum(int(p>=.5)==e[2] for p,e in zip(probs,data))/len(data)
 loss=-sum(e[2]*math.log(max(1e-9,p))+(1-e[2])*math.log(max(1e-9,1-p)) for p,e in zip(probs,data))/len(data)
 return accuracy,loss

def train_local(weights,examples,seed):
 w=list(weights);r=random.Random(seed)
 for _ in range(2):
  order=list(examples);r.shuffle(order)
  for x,y,label in order:
   err=sigmoid(w[0]*x+w[1]*y+w[2])-label
   w[0]-=.09*err*x;w[1]-=.09*err*y;w[2]-=.09*err
 return w

def simulate(seed,alpha):
 train,test=samples(seed)
 for n in range(100):
  partition=partitions(train,seed*1000+n,alpha)
  if partition is not None:break
 if partition is None:raise ValueError("no non-empty partitions")
 rows=[]
 for scenario in SCENARIOS:
  weights=[0.,0.,0.];completed=stalled=0
  for tick in range(1,25):
   active=[0,1,2]
   if scenario!="control" and tick>=6:active.remove(2)
   if scenario=="revoked_with_replacement" and tick>=10:active.append(3)
   if len(active)<QUORUM:stalled+=1
   else:
    updates=[(len(partition[k]),train_local(weights,partition[k],seed*100000+tick*100+k)) for k in active]
    total=sum(n for n,_ in updates)
    weights=[sum(n*vec[i] for n,vec in updates)/total for i in range(3)]
    completed+=1
   acc,loss=evaluate(weights,test)
   rows.append({"seed": seed, "alpha": alpha, "scenario": scenario, "slot": tick, "rounds_completed": completed, "stalled_slots": stalled, "active_workers": len(active), "accuracy": acc, "log_loss": loss})
 return rows

def main():
 parser=argparse.ArgumentParser()
 parser.add_argument("--out",type=Path,required=True)
 parser.add_argument("--seeds",type=int,default=12)
 parser.add_argument("--alpha",type=float,default=.3)
 args=parser.parse_args()
 if args.seeds<2 or args.alpha<=0:parser.error("seeds>=2, alpha>0")
 args.out.mkdir(parents=True,exist_ok=True)
 data=[row for seed in range(1,args.seeds+1) for row in simulate(seed,args.alpha)]
 with (args.out/"per_slot.csv").open("w",newline="") as f:
  writer=csv.DictWriter(f,fieldnames=list(data[0]));writer.writeheader();writer.writerows(data)
 summary=[]
 for scenario in SCENARIOS:
  final=[r for r in data if r["scenario"]==scenario and r["slot"]==24]
  for field in ("accuracy","log_loss","rounds_completed","stalled_slots"):
   values=[r[field] for r in final]
   summary.append({"scenario": scenario, "metric": field, "n": len(values), "mean": statistics.mean(values), "sd": statistics.stdev(values), "min": min(values), "max": max(values)})
 with (args.out/"summary.csv").open("w",newline="") as f:
  writer=csv.DictWriter(f,fieldnames=list(summary[0]));writer.writeheader();writer.writerows(summary)
 manifest={"kind": "synthetic_FL_availability_simulation", "network_or_Go_coordinator_tested": False, "quorum": 3, "initial_workers": [0,1,2], "revoked_worker": 2, "revoked_at_slot": 6, "reserve_worker": 3, "replacement_at_slot": 10, "slots": 24, "partition": "classwise_Dirichlet", "alpha": args.alpha, "seeds": list(range(1,args.seeds+1)), "model": "logistic_regression", "dataset": "synthetic_gaussian_binary_2d", "train_samples": 180, "test_samples": 60, "local_epochs": 2, "local_lr": .09, "aggregation": "weighted_FedAvg", "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
 (args.out/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
 print(json.dumps({"summary":summary}))
if __name__=="__main__":main()
