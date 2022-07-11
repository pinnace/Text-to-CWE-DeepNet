# CWE Classification with BERT

This repository contains code and models relating to CWE classification tasks.

The Model uses the [HuggingFace Transformers](https://huggingface.co/transformers/) implementation of BERT.

Refer to the directory specific documentation for usage.

## Directories

### `Models`

Contains the PyTorch models, as well as a Pickle'd `lookup_table.p`. All models are exported with default naming, so they can be loaded easily with a single PyTorch `model.from_pretrained(model_dir)`. The lookup table contains a hash map of CWE IDs to output ids (e.g. {255:0, 20:1, 267:2, ... } )

### `datasets`

All data gathered. Some raw, some curated. 

### `notebooks`

Jupyter notebooks used to train the models and one for the SciKit data pipeline. 

### `scripts`

Various utility scripts. Don't look at them, don't run them. The code is ugly as sin and depends on the repository being in a certain state. Can use them as reference if you want to scrape some sites.

## Usage

Usage does not yet have a standard interface, but to create a predict function, the following is neccessary:

- Import deps

Transformers lib must be installed
```python
git clone https://github.com/huggingface/transformers && cd transformers && pip install .
```

```python
import torch
from transformers import *
import pandas as pd
import numpy as np
import tensorflow as tf
```

- Load the lookup table

```python
data_dir = "../datasets/TrainingV3/TTVDatasets/"
lookup_table = pickle.load( open( data_dir + "lookup_table.p", "rb" ) )
```

- Load the CWE descriptions table

```python
cwe_lookup_table = pd.read_csv("../datasets/cwe-lookup-table.csv",index_col=False)
```

To lookup a certain CWE, you can do the following:
```python
>>> cwe_lookup_table.loc[cwe_lookup_table['CWE-ID'] == 255]["Description"].values[0]
'Credentials Management Errors'
```

where `255` is the CWE ID

- Load the model

```python
MODELS = (BertForSequenceClassification,       BertTokenizer,       'bert-large-cased-whole-word-masking')
model_class, tokenizer_class, pretrained_weights = MODELS

model_dir = '../Models/ModelV3/ModelBase/LargeCasedWWM/'
model = model_class.from_pretrained(model_dir)
model.eval() # Drop into evaluation mode. Disables dropout layers.
model.cuda() # It is recommended to use a GPU. But do not include this line if you are not running on a GPU
tokenizer = tokenizer_class.from_pretrained(model_dir)
```

- Create the prediction function. The following is just a rough guide. Many parts can be optimized or cleaned up (e.g. inverting the lookup table, global softmax layer).

```python
def predict(model: model_class, text: str, lookup_table: dict) -> tuple:

	# The free text must be encoded by the tokenizer. Transforms the sentence into Vector[int]
	encoded_sent = tokenizer.encode(sentence, add_special_tokens=True, max_length=MAX_LEN, pad_to_max_length=True)
	attention_mask = [int(token_id > 0) for token_id in encoded_sent]

	# Create the 1x512 tensors that the model operates on
	sent_tensor = torch.tensor([encoded_sent])
	attn_tensor = torch.tensor([attention_mask])

	# Speeds up calc when gradients don't need to be calculated
	with torch.no_grad():
		# Forward pass, calculate logit predictions
		outputs = model(sent_tensor, token_type_ids=None, attention_mask=attn_tensor)
		logits = outputs[0]

	# Move logits and labels to CPU
	logits = logits.detach().cpu().numpy()

	# Push the output through a Softmax layer.
	# This yields an actual probability.
	softie = torch.nn.Softmax(dim=1)
	preds = softie(torch.tensor(logits))

	# Grab the most likely. Can be modified to fetch top-n
	prediction = preds.argmax()

	# Find the actual CWE
	for k,v in lookup_table.items():
		if v == prediction:
			cwe = k
			break

	# Get this CWE's text definition
	description = cwe_lookup_table.loc[cwe_lookup_table['CWE-ID'] == cwe]["Description"].values[0]

	# Print out the prediction
	print("Input: {}\n\tPredicted CWE: {}: {}, Prob: {}".format(sentence, cwe, description, round(float(preds[0][prediction]),3)))

	# Return whatever you like
	return (cwe, description)
