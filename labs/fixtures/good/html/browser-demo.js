document.querySelector('#details').addEventListener('click', async () => {
const route = ['/browser', '-only.json'].join('');
const response = await fetch(route);
const details = await response.json();
document.querySelector('#result').textContent = details.message;
history.pushState({}, '', '#details');
});