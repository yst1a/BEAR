module loa8(input [7:0] a, b, output [7:0] y);
    // W = 8, k = 3. The high region is added accurately modulo 32.
    wire [4:0] high = a[7:3] + b[7:3] + (a[2] & b[2]);
    assign y = {high, (a[2:0] | b[2:0])};
endmodule

module loa_accumulator(input clk, rst_n, en, input [7:0] x,
                       output reg [7:0] sum);
    wire [7:0] next_sum;
    loa8 adder(.a(sum), .b(x), .y(next_sum));
    always @(posedge clk or negedge rst_n)
        if (!rst_n) sum <= 8'b0;
        else if (en) sum <= next_sum;
endmodule
