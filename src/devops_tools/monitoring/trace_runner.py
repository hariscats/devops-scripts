# Python script for debugging code using the trace module

import linecache  # Import linecache for trace_lines
import sys
import trace

# --- Custom Trace Functions (Optional: trace.Trace provides built-in tracing) ---
# You can uncomment and use these if you need highly customized trace output.
# def trace_calls(frame, event, arg):
#     """Trace function to log calls to other functions."""
#     if event != "call":
#         return
#     co = frame.f_code
#     func_name = co.co_name
#     if func_name == 'write':
#         # Ignore write() calls from printing
#         return
#     line_no = frame.f_lineno
#     filename = co.co_filename
#     print(f"Call to {func_name} on line {line_no} of {filename}")
#     return trace_calls # Return itself to continue tracing calls

# def trace_lines(frame, event, arg):
#     """Trace function to log executed lines within functions."""
#     if event != 'line':
#         return
#     co = frame.f_code
#     func_name = co.co_name
#     line_no = frame.f_lineno
#     filename = co.co_filename
#     # Use linecache to get the source line
#     line = linecache.getline(filename, line_no)
#     print(f"  {filename}:{line_no} ({func_name}): {line.strip()}")
#     return trace_lines # Return itself to continue tracing lines
# --- End Custom Trace Functions ---


def execute_script(filepath):
    """Execute the given Python file after compiling its source."""
    try:
        with open(filepath, "r") as f:
            # Using globals() and locals() provides a more standard execution environment
            global_vars = {"__name__": "__main__", "__file__": filepath}
            local_vars = global_vars
            code = compile(f.read(), filepath, "exec")
            exec(code, global_vars, local_vars)  # nosec
    except FileNotFoundError:
        print(f"Error: Script file not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error executing script {filepath}: {e}", file=sys.stderr)
        sys.exit(1)


def run_with_trace(filepath):
    """Set up tracing using trace.Trace and execute the specified Python script."""
    # Initialize the tracer.
    # trace=1 -> Trace line execution
    # count=0 -> Don't count number of times each line is executed
    # timing=True -> Add timestamps relative to the start of tracing
    tracer = trace.Trace(
        trace=1,
        count=0,
        timing=True,
        ignoredirs=[sys.prefix, sys.exec_prefix],  # Ignore standard library paths
    )

    # Run the target script's execution function under the tracer's control.
    # tracer.runctx is generally safer than runfunc for executing arbitrary code.
    print(f"--- Starting trace for {filepath} ---")
    try:
        # Pass an empty dict initially for globals/locals within runctx
        # The actual execution happens inside execute_script
        tracer.runctx(
            "execute_script(filepath)",
            globals={"execute_script": execute_script, "filepath": filepath},
            locals={},
        )
    finally:
        print(f"--- Ending trace for {filepath} ---")
        # Get trace results (optional, trace output is printed during execution)
        # results = tracer.results()
        # results.write_results(show_missing=True, coverdir=".") # Example: Write coverage data


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <script_to_trace.py>", file=sys.stderr)
        sys.exit(1)

    script_to_trace = sys.argv[1]

    # --- Choose tracing method ---
    # Method 1: Using trace.Trace (Recommended)
    run_with_trace(script_to_trace)

    # Method 2: Using sys.settrace with custom functions (Uncomment to use)
    # print(f"--- Starting custom trace for {script_to_trace} ---")
    # try:
    #     # Choose one: trace_calls or trace_lines
    #     sys.settrace(trace_lines)
    #     execute_script(script_to_trace)
    # finally:
    #     sys.settrace(None) # Disable tracing
    #     print(f"--- Ending custom trace for {script_to_trace} ---")
    # --- End Choose tracing method ---
