#! /usr/bin/env python3
import warnings

import atheris
import sys
import fuzz_helpers
import warnings

from contextlib import contextmanager
from io import BytesIO
# Disable stdout
@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = BytesIO()
    sys.stderr = BytesIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr

with atheris.instrument_imports(include=["pronto"]):
    import pronto
    warnings.filterwarnings("ignore", category=pronto.warnings.ProntoWarning)

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    should_conv = fdp.ConsumeBool()
    try:
        with fdp.ConsumeMemoryFile(all_data=True, as_bytes=True) as f, nostdout():
            ont = pronto.Ontology(handle=f)
            if should_conv:
                ont.dumps()
    except (UnicodeDecodeError, ValueError, LookupError):
        return -1
    except TypeError as e:
        if 'is required' in str(e):
            return -1
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
