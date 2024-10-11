import subprocess

def run_script_with_values(script_path, values):
    for value in values:
        subprocess.run(["python", script_path, "-p", "-i", str(value)])

if __name__ == "__main__":
    script_path = "sample.py"  # Path to your script
    values = [1200, 800]  # List of values for -i
    run_script_with_values(script_path, values)