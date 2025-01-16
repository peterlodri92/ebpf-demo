.PHONY: test create_user read_user update_user delete_user upload_file download_file openapi

test: create_user read_user update_user delete_user upload_file download_file

create_user:
	@echo "Creating user Alice..."
	@curl -X POST http://localhost:8000/users/ \
		-H "Content-Type: application/json" \
		-d '{"name": "Alice", "email": "alice@example.com"}'

read_user:
	@echo "Reading user with ID 1..."
	@curl http://localhost:8000/users/1

update_user:
	@echo "Updating user with ID 1..."
	@curl -X PUT http://localhost:8000/users/1 \
		-H "Content-Type: application/json" \
		-d '{"name": "Alice B", "email": "aliceb@example.com"}'

delete_user:
	@echo "Deleting user with ID 1..."
	@curl -X DELETE http://localhost:8000/users/1

upload_file:
	@echo "Uploading test file..."
	@curl -X POST http://localhost:8000/upload \
		-H "Content-Type: multipart/form-data" \
		-F "file=@test.txt"

download_file:
	@echo "Downloading test file..."
	@curl -O http://localhost:8000/download/test.txt

openapi:
	@echo "Generating OpenAPI schema..."
	@curl http://localhost:8000/openapi.json -o openapi.yaml
