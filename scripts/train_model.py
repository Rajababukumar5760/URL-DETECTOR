"""Train an optional baseline model from a user-supplied, documented CSV.

Expected columns: url,label where label is 1 for phishing and 0 for benign.
No dataset is downloaded automatically and synthetic rows are not included.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from app.url_analyzer import analyze_url, URLAnalysisError
from app.ml_model import FEATURE_COLUMNS, MODEL_PATH

def feature_row(url: str) -> dict:
    f = analyze_url(url)
    return {k: int(bool(f[k])) if isinstance(f[k], bool) else f[k] for k in FEATURE_COLUMNS}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', required=True, help='Path to a legitimate, labeled CSV with url,label columns')
    parser.add_argument('--label-column', default='label')
    parser.add_argument('--url-column', default='url')
    args = parser.parse_args()
    source = Path(args.csv)
    if not source.is_file(): parser.error(f'Dataset file not found: {source}')
    df = pd.read_csv(source)
    if args.url_column not in df or args.label_column not in df: parser.error('CSV must contain the configured URL and label columns.')
    df = df[[args.url_column, args.label_column]].dropna().copy()
    df[args.url_column] = df[args.url_column].astype(str).str.strip()
    df = df[df[args.url_column] != ''].drop_duplicates(subset=[args.url_column])
    labels = pd.to_numeric(df[args.label_column], errors='coerce')
    df = df[labels.isin([0,1])].copy(); df[args.label_column] = labels[labels.isin([0,1])].astype(int)
    if df[args.label_column].nunique() != 2 or df[args.label_column].value_counts().min() < 10:
        parser.error('Need both binary classes with at least 10 unique URL rows per class after cleaning.')
    rows=[]; keep=[]
    for idx, url in df[args.url_column].items():
        try: rows.append(feature_row(url)); keep.append(idx)
        except URLAnalysisError: pass
    df = df.loc[keep]
    X = pd.DataFrame(rows, index=keep, columns=FEATURE_COLUMNS)
    y = df[args.label_column]
    # Three independent partitions; duplicates are removed before splitting.
    X_train, X_hold, y_train, y_hold = train_test_split(X, y, test_size=.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_hold, y_hold, test_size=.50, random_state=42, stratify=y_hold)
    model = Pipeline([('imputer', SimpleImputer(strategy='most_frequent')), ('classifier', RandomForestClassifier(n_estimators=250, class_weight='balanced', random_state=42, n_jobs=-1, min_samples_leaf=2))])
    model.fit(X_train, y_train)
    # Validation is reported separately; test remains held until final evaluation.
    val_pred = model.predict(X_val); test_pred = model.predict(X_test)
    report = {
      'dataset_path': str(source.resolve()), 'dataset_rows_after_dedup_and_parse': int(len(X)),
      'class_distribution': {str(k): int(v) for k,v in y.value_counts().sort_index().items()},
      'split_sizes': {'train':len(X_train),'validation':len(X_val),'test':len(X_test)},
      'validation': {'accuracy':accuracy_score(y_val,val_pred),'precision':precision_score(y_val,val_pred,zero_division=0),'recall':recall_score(y_val,val_pred,zero_division=0),'f1':f1_score(y_val,val_pred,zero_division=0),'confusion_matrix':confusion_matrix(y_val,val_pred,labels=[0,1]).tolist()},
      'test': {'accuracy':accuracy_score(y_test,test_pred),'precision':precision_score(y_test,test_pred,zero_division=0),'recall':recall_score(y_test,test_pred,zero_division=0),'f1':f1_score(y_test,test_pred,zero_division=0),'confusion_matrix':confusion_matrix(y_test,test_pred,labels=[0,1]).tolist(),'classification_report':classification_report(y_test,test_pred,zero_division=0,output_dict=True)},
      'caveat': 'Metrics depend on dataset provenance, time period, labeling, and sampling; random splitting does not guarantee temporal or source-level independence.'
    }
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True); joblib.dump(model, MODEL_PATH)
    out=ROOT/'models'/'evaluation.json'; out.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2)); print(f'\nSaved model: {MODEL_PATH}\nSaved evaluation: {out}')
if __name__ == '__main__': main()
