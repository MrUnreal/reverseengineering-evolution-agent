#!/bin/bash
# Master analysis orchestrator - Run all analysis passes
set -e

echo "================================================================================"
echo "ASCENSION.EXE - COMPREHENSIVE REVERSE ENGINEERING ANALYSIS"
echo "================================================================================"

REPORTS_DIR="/reports"
OUTPUT_FILE="$REPORTS_DIR/MASTER_ANALYSIS.md"

echo "Starting comprehensive analysis at $(date)" | tee $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE

# Analysis Pass 1: Opcode Hunter
echo "[1/5] Running Opcode Hunter..." | tee -a $OUTPUT_FILE
python3 /app/opcode_hunter.py 2>&1 | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE

# Analysis Pass 2: String Analyzer  
echo "[2/5] Running String Analyzer..." | tee -a $OUTPUT_FILE
python3 /app/string_analyzer.py 2>&1 | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE

# Analysis Pass 3: Function Deep Analyzer
echo "[3/5] Running Function Deep Analyzer..." | tee -a $OUTPUT_FILE
python3 /app/function_deep_analyzer.py 2>&1 | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE

# Analysis Pass 4: Data Structure Analyzer
echo "[4/5] Running Data Structure Analyzer..." | tee -a $OUTPUT_FILE
python3 /app/data_structure_analyzer.py 2>&1 | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE

# Analysis Pass 5: Generate consolidated report
echo "[5/5] Generating consolidated documentation..." | tee -a $OUTPUT_FILE
python3 /app/generate_master_index.py 2>&1 | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE

echo "================================================================================" | tee -a $OUTPUT_FILE
echo "Analysis completed at $(date)" | tee -a $OUTPUT_FILE
echo "================================================================================" | tee -a $OUTPUT_FILE

# List all generated reports
echo "" | tee -a $OUTPUT_FILE
echo "Generated Reports:" | tee -a $OUTPUT_FILE
ls -lh $REPORTS_DIR/*.json | tee -a $OUTPUT_FILE

echo "" | tee -a $OUTPUT_FILE
echo "Master analysis log saved to: $OUTPUT_FILE"
