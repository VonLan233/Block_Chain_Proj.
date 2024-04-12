import numpy as np

with open('table1.csv', 'r') as file:
    line = file.readline()
    while True:
        line = file.readline()
        if not line:
            break
