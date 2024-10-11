import pandas as pd
import matplotlib.pyplot as plt
from scipy.stats import norm
import numpy as np

# Load the CSV file
data = pd.read_csv('medians_plot.csv')

# List of columns to compare
columns_to_compare = ['ARR', 'OR']

plt.figure(figsize=(10, 6))

# Loop through each column, fit a Gaussian, and plot
for column in columns_to_compare:
    values = data[column].dropna()  # Drop NaN values
    mu, std = norm.fit(values)
    
    # Plot the histogram
    plt.hist(values, bins=25, density=True, alpha=0.6, label=f'{column} Histogram')
    
    # Plot the PDF
    xmin, xmax = plt.xlim()
    x = np.linspace(xmin, xmax, 100)
    p = norm.pdf(x, mu, std)
    plt.plot(x, p, linewidth=2, label=f'{column} fit: $\mu={mu:.2f}, \sigma={std:.2f}$')

plt.title('Comparison of Gaussian Fits')
plt.xlabel('Value')
plt.ylabel('Density')
plt.legend()
plt.show()
