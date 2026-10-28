# Release 1.2.1 — 26/10/2026

- Hướng dẫn Phase 2–4 đọc output của bước trước; cùng thư mục run giữ toàn bộ artifact liên quan.
- Hỗ trợ trực tiếp extraction.json → analysis.json → preprocessing.json làm đầu vào phase tương ứng.
- Thêm --model / --models: dt, rf, lr, svm, cnb, xgb, danh sách dấu phẩy hoặc all. Tham số/grid từ train config giữ nguyên cho model được chọn; model không có spec dùng mặc định.
- Trial budget tính theo các model đã chọn, không bắt người dùng sửa lại JSON để chạy một model.
- Báo lỗi khi dùng marker sai phase, đổi thư mục output khi đang đọc kết quả hoặc chọn model mới ở test/scan.
- In lệnh bước tiếp có đường dẫn và bundle nếu đang scan.
- Hướng dẫn setup Windows, môi trường đã kích hoạt và xử lý ModuleNotFoundError; cập nhật README/bàn giao thành viên 2.

Không đổi Dataset, feature extraction, cách chia dữ liệu hoặc lựa chọn bằng validation. Đường dẫn raw Dataset của CLI 1.2.0 vẫn được hỗ trợ; không phải luồng được khuyến nghị. --evaluate vẫn chỉ train/validation; test cần --experiment ID --test riêng.
