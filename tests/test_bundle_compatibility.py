"""Regression for joblib bundles written before the phase-directory reorganization."""
import joblib

def test_load_preexisting_encoder_module_path(tmp_path, monkeypatch):
    from pypi_metadata_detector import preprocess as legacy_module
    from pypi_metadata_detector.phase3_preprocessing.preprocess import FeatureEncoder

    rows = [{"features": {"has_license": 1}, "text": "training text"}]
    encoder = FeatureEncoder().fit(rows)
    original = encoder.transform(rows)
    path = tmp_path / "legacy-encoder.joblib"
    assert legacy_module.FeatureEncoder is FeatureEncoder
    with monkeypatch.context() as context:
        context.setattr(FeatureEncoder, "__module__", "pypi_metadata_detector.preprocess")
        joblib.dump(encoder, path)
    restored = joblib.load(path)
    assert restored.__class__ is FeatureEncoder
    assert (original != restored.transform(rows)).nnz == 0
