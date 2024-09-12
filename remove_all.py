import os
import glob

csv_files = glob.glob('*.csv')

for file in csv_files:
  os.remove(file)
  print(f"Removed: {file}")