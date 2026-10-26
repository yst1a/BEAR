"""Explicit product interfaces for fixed-width modular accumulators."""
import re


def product_interface(width=32, input_width=8, *, mode="ACC", product_signed=False,
                      activation_signed=False, weight_signed=False):
    """Describe extension before the characterized, full-width adder.

    Signedness belongs to the product interface, not to the low-local identity.
    The accumulator remains a bit-vector modulo 2**width; no saturation is added.
    """
    if mode not in ("ACC", "MAC"):
        raise ValueError("MODE_REQUIRES_ACC_OR_MAC")
    if (not isinstance(width, int) or isinstance(width, bool)
            or not isinstance(input_width, int) or isinstance(input_width, bool)
            or input_width < 1 or width < 2 * input_width):
        raise ValueError("REQUIRE_WIDTH_AT_LEAST_TWICE_INPUT_WIDTH")
    if any(type(v) is not bool for v in (product_signed, activation_signed, weight_signed)):
        raise ValueError("SIGNED_FLAGS_REQUIRE_BOOL")
    if mode == "ACC" and (activation_signed or weight_signed):
        raise ValueError("ACC_HAS_PRODUCT_PORT_ONLY")
    if mode == "MAC" and product_signed != (activation_signed or weight_signed):
        raise ValueError("MAC_PRODUCT_SIGN_MUST_MATCH_OPERANDS")
    return dict(mode=mode, width=width, input_width=input_width,
                product_width=2*input_width, product_signed=product_signed,
                activation_signed=activation_signed, weight_signed=weight_signed,
                extension="sign" if product_signed else "zero",
                arithmetic="modulo_2_to_width", adder_operand_widths=[width, width])


def accumulator_interface_rtl(top, adder_module, width=32, input_width=8, **options):
    """Emit an ACC/MAC shell around an adder with ports a, b and y.

    The adder must be separately characterized at the accumulator width.
    Both reference and rewritten designs receive exactly this input extension.
    For u8 x s8, select MAC, product_signed=True, weight_signed=True.
    """
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", n) for n in (top, adder_module)):
        raise ValueError("INVALID_MODULE_IDENTIFIER")
    c = product_interface(width, input_width, **options)
    pw = c["product_width"]
    if c["mode"] == "ACC":
        ports = f"input [{pw-1}:0] prod_in"
        product = "prod_in"
    else:
        ports = f"input [{input_width-1}:0] a,b"
        if not c["product_signed"]:
            product = "a*b"
        else:
            # Mixed signed/unsigned operands are explicitly made signed before
            # multiplication. The added zero bit preserves the unsigned range.
            a = "$signed(a)" if c["activation_signed"] else "$signed({1'b0,a})"
            b = "$signed(b)" if c["weight_signed"] else "$signed({1'b0,b})"
            product = f"{a}*{b}"
    extended = ("{{" + str(width-pw) + "{prod[" + str(pw-1) + "]}},prod}"
                if c["product_signed"] and width > pw else "prod")
    return "\n".join([
        f"module {top}(input clk,rst_n,{ports},output [{width-1}:0] y);",
        f"wire [{pw-1}:0] prod={product};",
        f"wire [{width-1}:0] x={extended};",
        f"reg [{width-1}:0] acc;",
        f"wire [{width-1}:0] next_acc;",
        f"{adder_module} add_acc(.a(acc),.b(x),.y(next_acc));",
        "always @(posedge clk or negedge rst_n) if(!rst_n) acc<=0; else acc<=next_acc;",
        "assign y=acc;", "endmodule", ""])
