#!/usr/bin/env python3
import os
import sys

def create_project_structure():
    """Create the complete folder structure and files"""
    
    # Define folder structure
    folders = [
        'src',
        'tests', 
        'samples',
        'config',
        'quarantine'
    ]
    
    # Create folders
    for folder in folders:
        os.makedirs(folder, exist_ok=True)
        print(f"Created folder: {folder}/")
    
    # Create __init__.py files
    init_files = ['src/__init__.py', 'tests/__init__.py']
    for init_file in init_files:
        with open(init_file, 'w') as f:
            f.write('')
        print(f"Created: {init_file}")
    
    print("Project structure created successfully!")
    print("\nNow copy the code files from the previous response into each corresponding file.")

if __name__ == "__main__":
    create_project_structure()