module accumulator(input clk,rst_n,input [15:0] prod_in,output [31:0] y);
wire [31:0] x={16'b0,prod_in};
wire [7:0] lo_next = l | x[7:0];
wire kappa = l[7] & x[7];
reg [7:0] l;
reg [23:0] S; reg [5:0] cb;
wire [23:0] xh=x[31:8];
wire [23:0] Cw;
wire [4:0] t_0={1'b0,S[3:0]}+{1'b0,xh[3:0]}+kappa;
assign Cw[0] = 1'b0;
assign Cw[3:1] = '0;
wire [4:0] t_1={1'b0,S[7:4]}+{1'b0,xh[7:4]}+cb[1];
assign Cw[4] = cb[1];
assign Cw[7:5] = '0;
wire [4:0] t_2={1'b0,S[11:8]}+{1'b0,xh[11:8]}+cb[2];
assign Cw[8] = cb[2];
assign Cw[11:9] = '0;
wire [4:0] t_3={1'b0,S[15:12]}+{1'b0,xh[15:12]}+cb[3];
assign Cw[12] = cb[3];
assign Cw[15:13] = '0;
wire [4:0] t_4={1'b0,S[19:16]}+{1'b0,xh[19:16]}+cb[4];
assign Cw[16] = cb[4];
assign Cw[19:17] = '0;
wire [4:0] t_5={1'b0,S[23:20]}+{1'b0,xh[23:20]}+cb[5];
assign Cw[20] = cb[5];
assign Cw[23:21] = '0;
always @(posedge clk or negedge rst_n) begin
 if(!rst_n) begin S<='0; cb<='0; l<='0; end
 else begin
  S[3:0] <= t_0[3:0];
  cb[1] <= t_0[4];
  S[7:4] <= t_1[3:0];
  cb[2] <= t_1[4];
  S[11:8] <= t_2[3:0];
  cb[3] <= t_2[4];
  S[15:12] <= t_3[3:0];
  cb[4] <= t_3[4];
  S[19:16] <= t_4[3:0];
  cb[5] <= t_4[4];
  S[23:20] <= t_5[3:0];
  cb[0] <= 1'b0;
  l <= lo_next;
 end
end
wire [23:0] decoded = S + Cw;
assign y = {decoded,l};
endmodule
