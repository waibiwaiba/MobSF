@echo off

if [%1]==[] goto usage
SET conf=%1
goto :run
:usage
SET conf="0.0.0.0:8000 [::]:8000"
@REM 自己的设置
@REM SET MOBSF_DEBUG=1
SET MOBSF_API_KEY=SeeWhatYouHaveRatherWhatYouDoNotHave
@REM SET MOBSF_HOME_DIR=F:\MobSF
:run
echo Running MobSF on %conf%
poetry run waitress-serve --listen=%conf% --threads=10 --channel-timeout=3600 mobsf.MobSF.wsgi:application