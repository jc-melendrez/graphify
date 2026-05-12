# Graphify API Documentation

This RESTful API allows users to upload CSV/Excel files and retrieve chart-ready data for Google Charts.

## Base URL

```
http://localhost:8000/api/
```

## API Endpoints

### 1. List All Datasets
Get all uploaded datasets.

**Endpoint:** `GET /api/datasets/`

**Response:**
```json
{
  "count": 1,
  "next": null,
  "previous": null,
  "results": [
    {
      "id": 1,
      "name": "Sales Data",
      "file": "datasets/sales_data_abc123.csv",
      "file_type": "csv",
      "created_at": "2026-05-12T15:00:00Z",
      "rows_count": 100
    }
  ]
}
```

### 2. Create New Dataset
Upload a new CSV or Excel file.

**Endpoint:** `POST /api/datasets/`

**Request Body (multipart/form-data):**
- `name` (required): Dataset name
- `file` (required): CSV or Excel file

**Example (cURL):**
```bash
curl -X POST http://localhost:8000/api/datasets/ \
  -F "name=Sales Data" \
  -F "file=@path/to/your/file.csv"
```

**Response (201 Created):**
```json
{
  "id": 1,
  "name": "Sales Data",
  "file": "datasets/sales_data_abc123.csv",
  "file_type": "csv",
  "created_at": "2026-05-12T15:00:00Z",
  "rows_count": 100
}
```

### 3. Get Dataset Details
Get specific dataset information.

**Endpoint:** `GET /api/datasets/{id}/`

**Response:**
```json
{
  "id": 1,
  "name": "Sales Data",
  "file": "datasets/sales_data_abc123.csv",
  "file_type": "csv",
  "created_at": "2026-05-12T15:00:00Z",
  "rows_count": 100
}
```

### 4. Update Dataset
Update dataset name (file cannot be changed).

**Endpoint:** `PUT /api/datasets/{id}/`

**Request Body:**
```json
{
  "name": "Updated Sales Data"
}
```

### 5. Delete Dataset
Delete a dataset.

**Endpoint:** `DELETE /api/datasets/{id}/`

### 6. Get Chart-Ready Data
Get parsed data formatted for Google Charts.

**Endpoint:** `GET /api/datasets/{id}/graph/`

**Response:**
```json
{
  "dataset_id": 1,
  "dataset_name": "Sales Data",
  "columns": ["Date", "Sales", "Profit"],
  "data": [
    {"Date": "2026-01-01", "Sales": 1000, "Profit": 200},
    {"Date": "2026-01-02", "Sales": 1200, "Profit": 250}
  ],
  "chart_type": "line",
  "title": "Sales Data",
  "total_rows": 100,
  "total_columns": 3
}
```

### 7. Parse CSV File
Parse uploaded CSV file and return structured data (without saving).

**Endpoint:** `POST /api/parse-csv/`

**Request Body (multipart/form-data):**
- `file` (required): CSV file
- `delimiter` (optional): Column delimiter (default: comma)
- `header_row` (optional): Header row number (default: 0)

**Example (cURL):**
```bash
curl -X POST http://localhost:8000/api/parse-csv/ \
  -F "file=@path/to/file.csv" \
  -F "delimiter=;"
```

**Response:**
```json
{
  "columns": ["Date", "Sales", "Profit"],
  "data": [
    {"Date": "2026-01-01", "Sales": 1000, "Profit": 200},
    {"Date": "2026-01-02", "Sales": 1200, "Profit": 250}
  ],
  "total_rows": 100,
  "total_columns": 3
}
```

### 8. Get Statistics
Get statistics about all datasets.

**Endpoint:** `GET /api/stats/`

**Response:**
```json
{
  "total_datasets": 5,
  "total_rows": 1500
}
```

## Google Charts Integration

The `/api/datasets/{id}/graph/` endpoint returns data in a format compatible with Google Charts:

```javascript
// Example usage in frontend
fetch('http://localhost:8000/api/datasets/1/graph/')
  .then(response => response.json())
  .then(data => {
    // Create Google Charts DataTable
    const dataTable = new google.visualization.DataTable();
    dataTable.addColumn('string', data.columns[0]);
    dataTable.addColumn('number', data.columns[1]);
    
    // Add rows
    data.data.forEach(row => {
      dataTable.addRow([row[data.columns[0]], row[data.columns[1]]]);
    });
    
    // Create chart
    const chart = new google.visualization.LineChart(document.getElementById('chart_div'));
    chart.draw(dataTable, {
      title: data.title,
      width: '100%',
      height: '400px'
    });
  });
```

## Supported File Formats

- **CSV** (Comma Separated Values)
- **Excel** (.xlsx and .xls)

## Error Responses

All errors return HTTP status codes and JSON error messages:

- **400 Bad Request**: Validation error
- **404 Not Found**: Dataset not found
- **500 Internal Server Error**: Server error

**Example Error Response:**
```json
{
  "error": "Only CSV and Excel files are allowed"
}
```

## Rate Limiting

The API has built-in rate limiting:
- Anonymous users: 100 requests per day
- Authenticated users: 1000 requests per day

## Permissions

Currently set to `AllowAny` (no authentication required). To enable Firebase authentication, change the permission class in `views.py`:
```python
permission_classes = [IsAuthenticated]
```

## Media Storage

Uploaded files are stored in the `media/datasets/` directory.

## Testing with Postman

1. Import the API documentation as a collection
2. Set base URL to `http://localhost:8000/api/`
3. Use the provided examples for each endpoint
4. Test the file upload and chart data endpoints