"""Fitted train-only numeric/text encoding persisted with the classifiers."""
import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from ..common import ToolError
from .dataset import assign_splits

class FeatureEncoder:
    def __init__(self, max_features=3000, ngram_max=2):
        self.max_features = max_features
        self.ngram_max = ngram_max

    def fit(self, records):
        if not records:
            raise ToolError("empty_training_records")
        self.feature_keys_ = set(records[0]["features"])
        self.numeric_ = DictVectorizer(sparse=True)
        self.numeric_.fit([r["features"] for r in records])
        self.text_ = TfidfVectorizer(max_features=self.max_features,
                                   ngram_range=(1, self.ngram_max), sublinear_tf=True,
                                   token_pattern=r"(?u)\b\w+\b")
        try:
            self.text_.fit([r["text"] for r in records])
        except ValueError as exc:
            if "empty vocabulary" not in str(exc):
                raise
            self.text_ = None
        self.feature_names_ = ["meta:" + n for n in self.numeric_.get_feature_names_out()]
        if self.text_ is not None:
            self.feature_names_ += ["text:" + n for n in self.text_.get_feature_names_out()]
        return self

    def transform(self, records):
        if not hasattr(self, "numeric_"):
            raise ToolError("preprocessor_not_fitted")
        if any(set(r["features"]) != self.feature_keys_ for r in records):
            raise ToolError("feature_contract_mismatch")
        if not records:
            return csr_matrix((0, len(self.feature_names_)), dtype=np.float64)
        numeric = self.numeric_.transform([r["features"] for r in records])
        if self.text_ is None:
            return numeric.tocsr()
        text = self.text_.transform([r["text"] for r in records])
        return hstack([numeric, text], format="csr")

    def fit_transform(self, records):
        return self.fit(records).transform(records)



def prepare_training(records, config, progress):
    """Split before fitting; validation and test only use transform."""
    splits = assign_splits(records, config["seed"])
    parts = {name: [r for r, split in zip(records, splits) if split == name]
             for name in ("train", "validation", "test")}
    progress.say("Phase 3 | " + " | ".join(f"{name}: {len(rows)}" for name, rows in parts.items()))
    encoder = FeatureEncoder(config["max_features"], config["ngram_max"])
    matrices = {"train": encoder.fit_transform(parts["train"])}
    for name in ("validation", "test"):
        matrices[name] = encoder.transform(parts[name])
    progress.say(f"Phase 3 hoàn thành | Features: {len(encoder.feature_names_)} | Fit: train only")
    return splits, parts, encoder, matrices
