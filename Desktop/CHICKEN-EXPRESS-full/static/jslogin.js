document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const errorMessage = document.querySelector('.error-message');

    form.addEventListener('submit', function(event) {
        // تحقق من صحة البيانات المدخلة
        if (!usernameInput.value || !passwordInput.value) {
            event.preventDefault();
            errorMessage.textContent = 'يرجى ملء جميع الحقول.';
        }
    });

    // يمكن إضافة المزيد من الوظائف هنا مثل التحقق من الصحة على الطيران
    usernameInput.addEventListener('input', function() {
        if (usernameInput.value) {
            errorMessage.textContent = '';
        }
    });

    passwordInput.addEventListener('input', function() {
        if (passwordInput.value) {
            errorMessage.textContent = '';
        }
    });
});
