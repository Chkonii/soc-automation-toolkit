import argparse
import json
import time
import os
from pandas_analyzer import analyze_with_pandas
from analyzer import analyze_with_python
from fpdf import FPDF



def write_pdf_report(report_text, output_filename):
    print("Generating PDF Document")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=14)
    pdf.multi_cell(0, 5, txt=report_text)
    pdf.output(output_filename)

def main():
    parser = argparse.ArgumentParser(description="SSH Brute Force Detector")

    parser.add_argument("--input", required=True, help="Path to the CSV file")
    parser.add_argument("--analyzer", choices=['python', 'pandas'], default='python', help="Which analyzer to use")
    parser.add_argument("--output", default="Report.txt", help="Output report filename")


    parser.add_argument("--ip-threshold", type=int, default=5, help="Failed attempts to flag an IP")
    parser.add_argument("--user-threshold", type=int, default=3, help="Failed attempts to flag an User")
    parser.add_argument("--burst-threshold", type=int, default=4, help="Attempts within burst window to flag")
    parser.add_argument("--burst-window", type=int, default=10, help="Burst detection window in seconds")
    parser.add_argument("--format", choices=['text', 'json', 'pdf'], default='text', help='output format')

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: File '{args.input}' does not exist")
        return

    print(f"Analyzing {args.input} with {args.analyzer} engine")
    start_time = time.time()


    if args.analyzer == "pandas":
        report_text, report_data = analyze_with_pandas(args.input, args.ip_threshold, args.user_threshold, args.burst_threshold, args.burst_window)
    else:
        report_text, report_data = analyze_with_python(args.input, args.ip_threshold, args.user_threshold, args.burst_threshold, args.burst_window)
    
    if report_text is None:
        print("Analysis failed to return error")
        return

    elapsed = time.time() - start_time
    print(f"[*] Analysis complete in {elapsed:.2f} seconds!")
    print(f"[*] Saving report to {args.output}...")

    if args.format == "pdf":
        write_pdf_report(report_text, args.output)
    elif args.format == "json":
        with open(args.output, "w") as file:
            json.dump(report_data, file, indent=4)
    else:
        with open(args.output, "w") as file:
            file.write(report_text)
    
    print("Done")


if __name__ == "__main__":
    main()










