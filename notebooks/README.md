# Jupyter Notebooks.

These should be pretty self explanatory.

## Data Pipeline

`Data-Cleaning-Pipeline.ipynb` merges CVE, CWE Schema, and X-Force datasets and performs the following, in this order:

- Merge
- Strip version numbers, as they add nothing and confound the model
- Strip spurious whitespace
- Removes underrepresented CWEs. These are CWEs with < threshold # of examples (currently 5). 
- Create the lookup table 
	- The lookup table is necessary because the CWEs are not a continuous set. The lookup table maps CWEs to a continuous set of output ids and viceversa. 
- Use a `StratifiedShuffleSplit` to create training, test, and validation sets. Stratified sampling ensures that examples are proportionally spread across the data sets.
- Writes out the training-ready datasets to either `datasets/TrainingV2/` or `datasets/TrainingV3/TTVDatasets`

## Model Training

The rest of the notebooks handle model training. They are self-documenting.
