"""Block carry-retaining accumulator generation."""

def block_accumulator_rtl(top: str, b: int, k: int = 0, width: int = 32, input_width: int = 16,
                          *, enable=False, low_function=None, expose_state=False) -> str:
    """Emit a reset-zero accumulator with registered cross-block carries."""
    if b not in (2, 4) or not 0 <= k < width or not 0 < input_width <= width:
        raise ValueError("Require b=2 or 4, 0 <= k < width, and 0 < input_width <= width")
    W = width
    H = W - k
    n = (H + b - 1) // b
    lines = [f"module {top}(input clk,rst_n,input [{input_width-1}:0] prod_in,output [{W-1}:0] y);",
             f"wire [{W-1}:0] x={{{W-input_width}'b0,prod_in}};" if input_width<W else f"wire [{W-1}:0] x=prod_in;"]
    extra=(',input en' if enable else '')
    if expose_state:
        extra+=f',output [{H-1}:0] os,oc'+(f',output [{k-1}:0] ol' if k else '')
    if extra:lines[0]=lines[0].replace(');',extra+');')
    if k:
        lines += [f"wire [{k-1}:0] lo_next = l | x[{k-1}:0];",
                  f"wire kappa = l[{k-1}] & x[{k-1}];",
                  f"reg [{k-1}:0] l;", f"reg [{H-1}:0] S; reg [{n-1}:0] cb;",
                  f"wire [{H-1}:0] xh=x[{W-1}:{k}];"]
        if low_function:
            lines[2:4]=[f'wire [{k}:0] low_result=lowfn(l,x[{k-1}:0]);',
                        f'wire [{k-1}:0] lo_next=low_result[{k-1}:0];',f'wire kappa=low_result[{k}];']
            lines+=list(low_function)
    else:
        lines += [f"reg [{W-1}:0] S; reg [{n-1}:0] cb;",
                  f"wire [{W-1}:0] xh=x;"]
    lines += [f"wire [{H-1}:0] Cw;"]
    for j in range(n):
        lo, hi = j*b, min((j+1)*b, H)-1
        bw = hi-lo+1
        cin = "kappa" if (j == 0 and k) else ("1'b0" if j == 0 else f"cb[{j}]")
        cbit = "1'b0" if j == 0 else f"cb[{j}]"
        lines.append(f"wire [{bw}:0] t_{j}={{1'b0,S[{hi}:{lo}]}}+{{1'b0,xh[{hi}:{lo}]}}+{cin};")
        lines.append(f"assign Cw[{lo}] = {cbit};")
        if bw > 1: lines.append(f"assign Cw[{hi}:{lo+1}] = '0;")
    lines += ["always @(posedge clk or negedge rst_n) begin",
              " if(!rst_n) begin S<='0; cb<='0;" + (" l<='0;" if k else "") + " end",
              " else if(en) begin" if enable else " else begin"]
    for j in range(n):
        lo, hi = j*b, min((j+1)*b, H)-1
        bw = hi-lo+1
        lines.append(f"  S[{hi}:{lo}] <= t_{j}[{bw-1}:0];")
        if j < n-1: lines.append(f"  cb[{j+1}] <= t_{j}[{bw}];")
    lines.append("  cb[0] <= 1'b0;")
    if k: lines.append("  l <= lo_next;")
    lines += [" end", "end", f"wire [{H-1}:0] decoded = S + Cw;",
              ("assign y = {decoded,l};" if k else "assign y = decoded;"), "endmodule", ""]
    if expose_state:
        lines.insert(-2,'assign os=S; assign oc=Cw;'+(' assign ol=l;' if k else ''))
    return "\n".join(lines)

