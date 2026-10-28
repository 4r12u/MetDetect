# Cấu hình thí nghiệm Phase 4 — 1.2.1

CLI: `--evaluate .\outputs\run-01 --model dt,lr --train-config FILE`. --model (hoặc --models) chọn thuật toán cần chạy; các params/grid cùng tên trong file vẫn giữ. Model không có trong file dùng mặc định. --model all chọn đủ sáu model. Bỏ --model thì giữ danh sách trong file; không có file thì mặc định cả sáu. Budget max_trials tính trên các model được chọn; file vẫn phải hợp lệ kể cả spec không được chọn. Không đổi model ở lệnh --test hoặc --bundle. Xem SETUP_WINDOWS.md cho cài đặt và luồng output → output.

`--train-config FILE` chỉ dùng khi tạo thí nghiệm bằng `--evaluate`. Không sửa analysis config hay cache Phase 3. Các key không được hỗ trợ bị từ chối; không import class hoặc thực thi biểu thức từ JSON.

| Key | Ý nghĩa |
|---|---|
| seed | Seed model (0 đến 2^32-1); seed chia dữ liệu thuộc Phase 3 và không đổi ở đây |
| jobs | Số luồng RF/XGBoost, 1–64 |
| selection_metric | malicious_f1 (mặc định), malicious_recall, malicious_precision, macro_f1, accuracy, roc_auc hoặc average_precision |
| max_trials | Giới hạn tổng cấu hình trước khi chạy, 1–100; không cắt grid ngầm |
| top_k | Số feature quan trọng xuất ra, 1–200 |
| thresholds | Tùy chọn danh sách probability trong [0,1] và decision là số hữu hạn; tối đa 31 giá trị/loại |
| models | Object các model cần chạy: dt, rf, lr, svm, cnb, xgb |

Mỗi model có `params` là tham số cố định và `grid` là các danh sách giá trị. Grid dùng tích Descartes; nếu một key ở cả params/grid thì grid ghi đè. Ví dụ `{"models":{"lr":{"params":{"max_iter":3000},"grid":{"C":[0.1,1.0,10.0]}}}}` chạy ba cấu hình LR.

| Model | Tham số cho phép |
|---|---|
| dt | max_depth, min_samples_leaf, min_samples_split, max_features, class_weight, criterion |
| rf | n_estimators, max_depth, min_samples_leaf, min_samples_split, max_features, class_weight |
| lr / svm | C, max_iter, class_weight, tol |
| cnb | alpha, norm, fit_prior |
| xgb | n_estimators, max_depth, learning_rate, subsample, colsample_bytree, min_child_weight, reg_alpha, reg_lambda, scale_pos_weight |

RF/DT/LR/SVM mặc định class_weight=balanced. XGBoost scale_pos_weight mặc định của thư viện, không tự cân bằng; có thể đặt bằng tỷ lệ lớp trong train. Dataset cân bằng không bắt buộc tăng trọng số. CNB không có class_weight. Các giá trị sai miền được thư viện báo lỗi và ghi riêng theo trial.

Thử threshold trên validation sau mỗi lần fit. Mặc định luôn là một ứng viên: dùng chính model.predict; nếu bằng điểm, giữ ứng viên xuất hiện trước (mặc định trước). Probability của model mặc định thường có ngưỡng .5, decision của SVM thường 0; giá trị null trong kết quả nghĩa là dùng model.predict, không giả lập lại quy tắc tie-break. Ngưỡng chốt được lưu trong bundle và dùng cả khi scan/test.

Giữa các cấu hình của cùng model và giữa các model, điểm selection_metric bằng nhau giữ thứ tự xuất hiện trong JSON. Bảng xếp hạng metric cho các model đồng điểm cùng hạng. Thời gian thấp hơn, FP/FN thấp hơn tốt hơn; các metric chất lượng cao hơn tốt hơn. Thời gian predict đo tạo score và nhãn cho toàn split, không gồm IO/encoding; chưa phải benchmark vận hành ổn định.

Thông tin thí nghiệm ghi dataset_identity (hash của sample IDs, nhãn, nhóm, metadata digest và split), source_digest (cả analysis/record) và preprocessing_digest (bao gồm hash encoder/X). Đây là identity dữ liệu đã xử lý, không thay cho audit lại checksum từng archive. experiment.json lưu phiên bản Python/thư viện; test chặn mismatch thư viện liên quan. XGBoost có mặc định missing=NaN; metadata effective_params ghi sentinel này dưới chuỗi "NaN" để JSON hợp lệ, không phải giá trị cấu hình người dùng.

Không có calibration hoặc SHAP/permutation importance ở bản này. Top Feature dùng importance/hệ số native, có tên cột và phương pháp cụ thể. Với CNB, chênh lệch feature_log_prob_[1]-feature_log_prob_[0] mô tả chiều đóng góp vào chênh lệch điểm hai lớp, không gọi là xác suất feature. LR/SVM dùng hệ số sau MaxAbsScaler nên không so độ lớn trực tiếp với đơn vị raw hoặc với model khác.

Tài liệu API: [LinearSVC](https://scikit-learn.org/1.7/modules/generated/sklearn.svm.LinearSVC.html), [MaxAbsScaler](https://scikit-learn.org/1.7/modules/generated/sklearn.preprocessing.MaxAbsScaler.html), [ComplementNB](https://scikit-learn.org/1.7/modules/generated/sklearn.naive_bayes.ComplementNB.html), [XGBoost](https://xgboost.readthedocs.io/en/stable/python/python_api.html).
