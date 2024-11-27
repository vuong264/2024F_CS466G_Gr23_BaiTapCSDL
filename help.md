# Hướng dẫn sử dụng Flask

## Giới thiệu
Đây là một ứng dụng quản lý người dùng đơn giản được xây dựng bằng Flask, SQLAlchemy và Flask-Login. Ứng dụng hỗ trợ chức năng đăng ký, đăng nhập, quản lý người dùng và quản lý nội dung.

## Yêu cầu
- Python 3.x
- Các thư viện cần thiết (đã liệt kê trong `requirement.txt`)

## Cài đặt
1. Tải mã nguồn về.
2. Tạo một môi trường ảo:
    ```bash
    python -m venv venv
    ```
3. Kích hoạt môi trường ảo:
    - Trên Windows:
        ```bash
        venv\Scripts\activate
        ```
    - Trên macOS/Linux:
        ```bash
        source venv/bin/activate
        ```
4. Cài đặt các thư viện cần thiết:
    ```bash
    pip install -r requirements.txt
    ```

## Cấu hình
1. Chỉnh sửa file `config.py` để thiết lập các thông tin cơ sở dữ liệu và khóa bí mật.
2. Thiết lập biến môi trường cho `SECRET_KEY` nếu cần.

## Chạy ứng dụng
Để chạy ứng dụng, hãy sử dụng lệnh sau trong thư mục gốc của dự án:
```bash
python run.py