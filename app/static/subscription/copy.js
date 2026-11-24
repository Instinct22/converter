const copyButton = document.getElementById('copy');
const copyLabel = document.getElementById('copy-label');
const manualCopy = document.getElementById('manual-copy');
const manualUrl = document.getElementById('copy-url');
let resetLabel;

copyButton.hidden = false;
copyButton.addEventListener('click', async () => {
  clearTimeout(resetLabel);
  try {
    await navigator.clipboard.writeText(copyButton.dataset.url);
    manualCopy.hidden = true;
    copyLabel.textContent = 'Скопировано';
    resetLabel = setTimeout(() => { copyLabel.textContent = 'Скопировать ссылку'; }, 1800);
  } catch {
    copyLabel.textContent = 'Скопировать ссылку';
    manualUrl.value = copyButton.dataset.url;
    manualCopy.hidden = false;
    manualUrl.focus();
    manualUrl.select();
  }
});
