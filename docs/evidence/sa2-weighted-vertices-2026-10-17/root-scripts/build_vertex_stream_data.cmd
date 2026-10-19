@call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
@set "SF_STREAM_INCLUDES=/I weighted-stage/prepared/src /I C:\decomp\SonicFantasy-master\src /I C:\decomp\SonicFantasy-master\src\Misc /I C:\decomp\SonicFantasy-master\src\Importers\GameCube"
@cl /nologo /std:c++latest /EHsc /O2 /fp:strict /W4 /WX %SF_STREAM_INCLUDES% /c weighted-stage/prepared/src/Importers/SA2/ModelVertexTransform.cpp /Fo:weighted-stage/stream_transform.obj
@if errorlevel 1 exit /b 1
@cl /nologo /std:c++latest /EHsc /O2 /fp:strict /W4 /WX %SF_STREAM_INCLUDES% /c C:\decomp\SonicFantasy-master\src\Importers\SA2\ModelData.cpp /Fo:weighted-stage/stream_model_data.obj
@if errorlevel 1 exit /b 1
@cl /nologo /std:c++latest /EHsc /O2 /fp:strict /W4 /WX %SF_STREAM_INCLUDES% /c vertex_stream_data_check_iso.cpp /Fo:weighted-stage/vertex_stream_data_check_iso.obj
@if errorlevel 1 exit /b 1
@link /nologo weighted-stage/stream_transform.obj weighted-stage/stream_model_data.obj weighted-stage/vertex_stream_data_check_iso.obj rel-validation/sa2_prs.obj rel-validation/shadow_prs.obj rel-validation/gc_disc.obj /OUT:weighted-stage/vertex_stream_data_check_iso.exe
@exit /b %errorlevel%
