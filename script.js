// script.js
const ta = document.querySelector('textarea');
if (ta) ta.focus();

const btn = document.getElementById('copyBtn');
if (btn) {
    btn.addEventListener('click', async (e) => {
        e.preventDefault();
        const inp = document.getElementById('secretLink');
        try {
            await navigator.clipboard.writeText(inp.value);
            btn.textContent = 'Copiato!';
        } catch (err) {
            console.error(err);
        }
        setTimeout(() => btn.textContent = 'Copia', 2000);
    });
}
