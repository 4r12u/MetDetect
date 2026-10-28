# Release 1.2.0 — 26/10/2026

- Sáu model: DT, RF, Logistic Regression, Linear SVM, Complement Naive Bayes, XGBoost (extra ml).
- Cấu hình model/tuning riêng, không cần chạy lại Phase 1–3 khi chỉ đổi tham số model.
- Mỗi thí nghiệm có thư mục và ID riêng; giữ trial lỗi/cảnh báo, không chọn cấu hình chưa hội tụ.
- Chọn tham số/model/ngưỡng bằng validation. Test yêu cầu --experiment ID --test, không tự chạy khi tuning.
- Ranking từng metric, có đồng hạng; thêm ROC-AUC, Average Precision, Macro-F1, FP/FN và thời gian.
- Native Top Feature có tên feature/nhóm/cách tính/chiều tác động nếu áp dụng; không so trực tiếp importance giữa model.
- Xuất CSV/JSON, HTML offline có lọc lỗi, Top Model/Feature và lịch sử trial.
- SVM scan hỗ trợ decision score, không gọi predict_proba bắt buộc; ngưỡng đã chốt đi cùng bundle.
- Hướng dẫn bàn giao thành viên 2 và mẫu tuning 27 trial.

## Thay đổi giao diện cần biết

--evaluate trên dataset train không tạo bundle.joblib tại root run nữa; bundle nằm ở experiments/<ID>/. Test không còn chạy tự động. --metric/--visual mặc định dùng thí nghiệm hoàn thành gần nhất; có thể chọn --experiment ID. HTML có thêm thư mục ID để giữ các báo cáo cũ. Luồng sample --bundle và các subcommand cũ vẫn hỗ trợ.

Không thay archive/nhãn/split trong Dataset, không huấn luyện trên dataset nghiên cứu để công bố kết quả trong lần nâng cấp này. Kiểm thử dùng synthetic fixture; báo cáo QA không là hiệu quả phát hiện malware.
