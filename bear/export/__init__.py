"""Optional certificate-driven PyTorch and CUDA export."""

def export(certificate, output):
    from .export_torch import export as generate
    return generate(certificate, output)
