#!/usr/bin/env bash
# disas-func.sh <Image> <kallsyms> <symbol> [bytes]
# Disassemble a function from a raw arm64 Image using file offset = addr - _text,
# annotating bl targets with kallsyms names.
set -euo pipefail
IMG="$1"; KS="$2"; SYM="$3"; N="${4:-0x400}"
text=$(awk '$3=="_text"{print $1; exit}' "$KS")
addr=$(awk -v s="$SYM" '$3==s{print $1; exit}' "$KS")
[ -n "$addr" ] || { echo "no symbol $SYM"; exit 1; }
off=$(( 0x$addr - 0x$text ))
# name lookup for bl targets
python3 - "$IMG" "$KS" "$text" "$off" "$SYM" "$N" <<'PY'
import sys,struct,subprocess,bisect
img,ks,text,off,sym,n=sys.argv[1],sys.argv[2],int(sys.argv[3],16),int(sys.argv[4]),sys.argv[5],int(sys.argv[6],0)
syms=[]
for l in open(ks,errors="replace"):
    p=l.split(maxsplit=2)
    if len(p)<3: continue
    if p[2].strip().endswith("]"): continue
    try: syms.append((int(p[0],16),p[2].strip()))
    except: pass
syms.sort(); addrs=[a for a,_ in syms]
def nm(a):
    i=bisect.bisect_right(addrs,a)-1
    if i<0: return ""
    base,name=syms[i]; d=a-base
    return name if d==0 else f"{name}+{d:#x}"
data=open(img,"rb").read()[off:off+n]
open("/tmp/_f.bin","wb").write(data)
dis=subprocess.run(["aarch64-linux-gnu-objdump","-D","-b","binary","-m","aarch64",
    "--adjust-vma=%d"%(text+off),"/tmp/_f.bin"],capture_output=True,text=True).stdout
end=None
for line in dis.splitlines():
    line=line.rstrip()
    if ":\t" not in line: 
        continue
    a=line.split(":")[0].strip()
    try: va=int(a,16)
    except: continue
    ann=""
    # bl / b target annotation
    import re
    m=re.search(r"\b(bl|b|cbz|cbnz|tbz|tbnz|b\.\w+)\s+(0x[0-9a-f]+)",line)
    if m:
        tgt=int(m.group(2),16); ann="  ; -> %s"%nm(tgt)
        if "ret" in line: pass
    print(f"+{va-(text+off):#06x}  {line.split(chr(9),1)[1] if chr(9) in line else line}{ann}")
    if end is None and ("\tret" in line): end=va
    # stop a bit after first ret to keep output bounded
    if end is not None and va-end>0x20: break
PY
