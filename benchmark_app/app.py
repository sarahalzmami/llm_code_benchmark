from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
import time
from utils import rel

from services.results import ResultsService
from settings import settings

app = FastAPI(title=settings.app_name)
app.mount(
    "/static", StaticFiles(directory=str(rel(settings.static_dir))), name="static"
)
templates = Jinja2Templates(directory=str(rel(settings.templates_dir)))

_results = ResultsService(settings.results_path)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    headers, rows, latest_csv = _results.read_results()
    last_updated = (
        latest_csv.stat().st_mtime if latest_csv and latest_csv.exists() else None
    )
    last_updated_str = (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_updated))
        if last_updated
        else "—"
    )
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "headers": headers,
            "rows": rows,
            "has_data": bool(headers),
            "last_updated": last_updated_str,
            "open_source_url": settings.open_source_url,
        },
    )


@app.get("/api/results.csv")
def api_results_csv():
    csv_path = _results.find_latest_csv()
    if not csv_path or not csv_path.exists():
        raise HTTPException(status_code=404, detail="No results CSV found")
    return FileResponse(str(csv_path), filename=csv_path.name, media_type="text/csv")
