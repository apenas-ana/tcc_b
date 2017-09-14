import glob
import csv
import os
from sklearn.manifold import TSNE
import matplotlib 
matplotlib.use('Agg')
import matplotlib.pyplot as plt                                                                                                                  
from sklearn.metrics import accuracy_score
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction import DictVectorizer
from sklearn.model_selection import StratifiedKFold                                                                                                                       
from sklearn.metrics import confusion_matrix,accuracy_score
import numpy as np
from numpy.random import RandomState

def main():
	print('I''m in the main Bitch')