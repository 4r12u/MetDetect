# Setup Windows / PowerShell — 1.2.1

## 1. Chuẩn bị

Giải nén ZIP vào thư mục bạn chọn. Mở terminal ngay tại thư mục có README.md, pyproject.toml và pypi_metadata_detector/. Không chuyển vào thư mục package bên trong. Thư mục test mới hoàn toàn có thể khác nơi phát triển source; không cần dùng bất kỳ đường dẫn cũ nào.

Cần Python 64-bit >=3.10 và pip. Môi trường đã kiểm chứng là Python 3.10.21, Windows, CPU; không cần GPU hay API key. Kiểm tra:

```powershell
python --version
python -m pip --version
```

## 2. Tạo môi trường nếu chưa có

Nếu terminal đang dùng môi trường đã kích hoạt thì bỏ qua bước này. Chỉ tạo/kích hoạt một lần cho thư mục dự án mới:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Các lệnh bên dưới dùng `python` trực tiếp, không thêm đường dẫn .venv trước từng lệnh. Khi mở terminal mới, kích hoạt lại môi trường của chính thư mục đang dùng. Không sao chép .venv từ máy hoặc thư mục dự án khác.

## 3. Cài chính tool của nhóm

```powershell
python -m pip install -e ".[ml]"
python -m pypi_metadata_detector --version
python -m pypi_metadata_detector --help
```

Version phải là 1.2.1. `.[ml]` cài tool và XGBoost. Nếu chỉ cần dt/rf/lr/svm/cnb, có thể cài `python -m pip install -e .`. Đây là cài tool của nhóm; không chạy pip/setup.py/build/import đối với package mẫu trong Dataset.

Muốn tái lập bộ phiên bản thư viện đã kiểm chứng trên Python 3.10, dùng thêm `python -m pip install -r requirements-tested.txt` trước khi chạy thí nghiệm. File này gồm cả pytest để kiểm thử. Để chạy test: `python -m pip install -e ".[ml,test]"`, rồi `python -B -m pytest -p no:cacheprovider -q`.

Nếu gặp ModuleNotFoundError: kiểm tra đang ở thư mục có pyproject.toml, đúng Python/môi trường bằng `python -m pip --version`, rồi chạy lại lệnh cài tool trong chính terminal đó. Không khắc phục bằng chuyển vào thư mục pypi_metadata_detector/.

## 4. Đặt dataset và chạy

ZIP source không kèm dataset/môi trường/kết quả cũ. Đặt Dataset đã kiểm chứng cạnh README, giữ nguyên manifest.csv và các đường dẫn artifact tương đối. Một run mới nên dùng tên thư mục mới, ví dụ run-01:

```powershell
python -m pypi_metadata_detector --extraction .\Dataset --output .\outputs\run-01
python -m pypi_metadata_detector --analysis .\outputs\run-01
python -m pypi_metadata_detector --preprocessing .\outputs\run-01
python -m pypi_metadata_detector --evaluate .\outputs\run-01 --model dt --experiment dt-01
python -m pypi_metadata_detector --metric .\outputs\run-01 --experiment dt-01
python -m pypi_metadata_detector --visual .\outputs\run-01 --experiment dt-01
```

Phase 2–4 đọc artifact trong output trước, không cần đọc archive gốc. Kết quả mỗi phase được bổ sung trong outputs/run-01; các thí nghiệm riêng nằm trong experiments/<ID>. JSON marker không chứa toàn bộ dữ liệu: nếu bàn giao output cho thành viên 2, bàn giao cả thư mục run, không chỉ file preprocessing.json. Kèm source, cấu hình, phiên bản thư viện và reference liên quan. Không nạp bundle/encoder của nguồn không tin cậy.

Đường dẫn có dấu cách phải nằm trong nháy kép. Ví dụ `--analysis ".\outputs\my run"`. Tool in lệnh bước tiếp sau mỗi phase.

## 5. Tuning, test và báo cáo

```powershell
python -m pypi_metadata_detector --evaluate .\outputs\run-01 --model dt,rf,lr --train-config .\configs\training-tuning.json --experiment tuning-01 --metric --visual
```

Ví dụ này chỉ chạy grid của dt/rf/lr, giữ các params/grid trong file. Dùng --model all để chạy cả sáu. Đổi ID cho mỗi lần chạy mới; không ghi đè thí nghiệm cũ.

Sau khi chốt model và tham số bằng validation:

```powershell
python -m pypi_metadata_detector --evaluate .\outputs\run-01 --experiment tuning-01 --test --metric --visual
```

Không thêm --model vào lệnh test: nó dùng model/ngưỡng đã chốt. HTML nằm ở visual/run-01/tuning-01/index.html. Mở bằng trình duyệt, không cần web server. Không chọn lại model dựa vào test.

## Truyền trực tiếp file của phase trước

Thay cho thư mục, có thể dùng:

```powershell
python -m pypi_metadata_detector --analysis .\outputs\run-01\extraction.json
python -m pypi_metadata_detector --preprocessing .\outputs\run-01\analysis.json
python -m pypi_metadata_detector --evaluate .\outputs\run-01\preprocessing.json --model lr --experiment lr-02
```

Vẫn giữ đủ samples/, encoder, ma trận và các marker bên cạnh. Không đổi --output sang thư mục khác ở các bước này. Nếu muốn một run tách biệt, tạo từ Phase 1 với --output mới.
