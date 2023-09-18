# SecAutXcel.py

This Python script is designed to convert CSV files into Excel (.xlsx) format while performing some data processing and aggregation. It is especially useful for working with CSV files generated by Nessus, a vulnerability scanning tool, but can be adapted for other CSV formats as well.

## Prerequisites

1. **Python**: Ensure that you have Python installed on your system. You can download it from [python.org](https://www.python.org/downloads/).
    
2. **Excel**: This script relies on Excel for creating the output file in .xlsx format. Excel needs to be installed on your system.
    
3. **Dependencies**: This script uses the Pandas library for data manipulation and the Openpyxl library for Excel output. You can install these dependencies using pip:

````bash

pip -r requirements.txt
````   

## Getting Started

1. **Usage**: Run the script by executing it with Python. It will prompt you for the input CSV file path and the desired output file name.

````python
python SecAutXcel.py
````

## Instructions

1. Run the script, and you will be prompted to enter the path of the CSV file you want to process and the desired output file name.
    
2. The script will automatically add the ".xlsx" extension to the output file if it's not already provided.
    
3. The CSV file will be read, and any blank rows with empty "Risk" columns will be removed.
    
4. All the content of the file will be converted into strings. If this causes errors, you can try removing the line responsible for this conversion.
    
5. Some columns will be renamed: "Name" to "NAME," "CVE" to "CVE OFC," and "Host" to "IP."
    
6. The script will aggregate data based on the "NAME" column and join unique values in certain other columns, such as "Synopsis," "Description," "Solution," "See Also," "CVSS v3.0 Base Score," "CVSS v3.0 Temporal Score," "CVE OFC," "IP," "Protocol," and "Port."
    
7. The script calculates the "Risk Eff" column based on the "CVSS v3.0 Temporal Score" column, assigning risk levels ("Critical," "High," "Medium," or "TBD").
    
8. The processed data will be saved in an Excel file with two sheets: "Original_Data" and "Processed."
    
9. Check the output Excel file for your processed data.
    

## About

This script is provided by [github.com/ic3man31](https://github.com/ic3man31) to simplify the conversion and processing of CSV files, particularly those generated by Nessus. Feel free to adapt and modify it to suit your specific needs. If you encounter any issues or have suggestions for improvements, please submit them on the GitHub repository.

**Enjoy converting and processing your CSV files with ease!**
