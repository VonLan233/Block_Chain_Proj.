import pandas as pd
import numpy as np

with open('table2.csv', 'r') as file:
    line = file.readline()
    while True:
        line = file.readline()
        if not line:
            break
        
