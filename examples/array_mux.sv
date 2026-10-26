// Replace with the actual result mux, adapting only this documented interface.
// sel=0..N-1 selects one lane; all other codes return default_value.
module array_mux #(parameter WIDTH=8,N=4,SEL_WIDTH=3)
(input [SEL_WIDTH-1:0] sel,input [N*WIDTH-1:0] data,
 input [WIDTH-1:0] default_value,output reg [WIDTH-1:0] y);
integer i;
always @* begin
  y=default_value;
  for(i=0;i<N;i=i+1) if(sel==i) y=data[i*WIDTH +: WIDTH];
end
endmodule
