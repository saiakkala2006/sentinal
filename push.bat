@echo off
echo ========================================================
echo Pushing Sentinel to GitHub (https://github.com/saiakkala2006/sentinal.git)
echo ========================================================
echo Setting HTTP postBuffer to 500MB to support large pushes...
git config http.postBuffer 524288000
git status
git add .
git commit -m "feat: update Sentinel multi-agent detection, tests, and documentation"
git push -u origin main
if %ERRORLEVEL% equ 0 (
    echo ========================================================
    echo [SUCCESS] Successfully pushed to GitHub!
    echo ========================================================
) else (
    echo ========================================================
    echo [ERROR] Push failed. Check your GitHub authentication or network.
    echo ========================================================
)
pause
