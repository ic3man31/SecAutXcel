import pandas as pd

# Banner
def d_ban():
    banner = """
    
  █████████                      █████████               █████    █████ █████                   ████ 
 ███░░░░░███                    ███░░░░░███             ░░███    ░░███ ░░███                   ░░███ 
░███    ░░░   ██████   ██████  ░███    ░███  █████ ████ ███████   ░░███ ███    ██████   ██████  ░███ 
░░█████████  ███░░███ ███░░███ ░███████████ ░░███ ░███ ░░░███░     ░░█████    ███░░███ ███░░███ ░███ 
 ░░░░░░░░███░███████ ░███ ░░░  ░███░░░░░███  ░███ ░███   ░███       ███░███  ░███ ░░░ ░███████  ░███ 
 ███    ░███░███░░░  ░███  ███ ░███    ░███  ░███ ░███   ░███ ███  ███ ░░███ ░███  ███░███░░░   ░███ 
░░█████████ ░░██████ ░░██████  █████   █████ ░░████████  ░░█████  █████ █████░░██████ ░░██████  █████
 ░░░░░░░░░   ░░░░░░   ░░░░░░  ░░░░░   ░░░░░   ░░░░░░░░    ░░░░░  ░░░░░ ░░░░░  ░░░░░░   ░░░░░░  ░░░░░ 
                                                                                                     
                                                                                                     
                                                                                                     
 ░░░░░░░░░   ░░░░░░   ░░░░░░  ░░░░░   ░░░░░   ░░░░░░░░    ░░░░░  ░░░░░ ░░░░░  ░░░░░░   ░░░░░░  ░░░░░ 
                                                                                                     
                                                                                                     
                                    by: github.com/ic3man31
    
    
    """ 
    print(banner)

d_ban()

# Enter the file CSV file you want to process and how you want to save it
filepath_in = input('\nEnter the path of the CSV file: ').strip("'").strip("'")
file_out = input('\nEnter how you want to save the output file: ').strip("'").strip("'")

# Convert automatically the output of the file to xlsx
if not file_out.endswith(".xlsx"):
    file_out += ".xlsx"

# Convert the file from CSV to Excel
df = pd.read_csv(filepath_in, delimiter=",") # Delimiter can e also ; checkout the file first
df.dropna(subset=['Risk'], inplace=True) # Remove the blank rows that are empty on Risk column
df.to_excel(file_out, index=False, engine='openpyxl')

# Conver all the content of the file into strings
# This can cause some errors, if it's the case try to remove the following line
df = df.astype(str)
# Rename some columns.
df.rename(columns={'Name': 'NAME', 'CVE': 'CVE OFC', 'Host': 'IP'}, inplace=True)

# Function to join unique values
def custom_textjoin(arr):
    return ';'.join(set(arr))

# Group and aggregate data of the columns that you want to process
# The columns mentioned are classically data from the export of the report in csv format by Nessus
aggregation_functions = {
    'Synopsis': custom_textjoin,
    'Description': custom_textjoin,
    'Solution': custom_textjoin,
    'See Also': custom_textjoin,
    'CVSS v3.0 Base Score': custom_textjoin,
    'CVSS v3.0 Temporal Score': custom_textjoin,
    'CVE OFC': custom_textjoin,
    'IP': custom_textjoin,
    'Protocol': custom_textjoin,
    'Port': custom_textjoin,
}
processed_data = df[df.duplicated(subset='NAME', keep=False)].groupby('NAME').agg(aggregation_functions).reset_index()
# Reorder the columns in the desired order
desired_order = [
    'CVE OFC', 'IP', 'Protocol', 'Port', 'NAME', 'Synopsis', 'Description', 'Solution',
    'See Also', 'CVSS v3.0 Base Score', 'CVSS v3.0 Temporal Score'
]
processed_data = processed_data[desired_order]
# Function to calcute Risk based on CVSS v3.0 Temporal Score
def calculate_risk_eff(row):
    cvss_temp = row['CVSS v3.0 Temporal Score']

    if pd.notna(cvss_temp):
        cvss_temp = float(cvss_temp)
        if cvss_temp >= 9:
            return 'Critical'
        elif cvss_temp >= 7:
            return 'High'
        elif cvss_temp >= 3:
            return 'Medium'
        
    return 'TBD'

# Create the 'Risk Eff' column and apply the function
processed_data['Risk Eff'] = processed_data.apply(calculate_risk_eff, axis=1)

# Save to Excel with 2 sheet: Original_Data and Processed
with pd.ExcelWriter(file_out, engine='xlsxwriter') as writer:
    df.to_excel(writer, sheet_name='Original_Data', index=False)
    processed_data.to_excel(writer, sheet_name='Processed', index=False)