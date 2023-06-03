const togglePassword = document.querySelector("#togglePassword");
const password = document.querySelector("#password");
const toggleConfirmPassword = document.querySelector("#toggleConfirmPassword");
const confirm_password = document.querySelector("#confirm_password");

togglePassword.addEventListener("click", function () {
  /* toggle the type attribute */
  const type =
    password.getAttribute("type") === "password" ? "text" : "password";
  password.setAttribute("type", type);

  /* toggle the icon */
  this.classList.toggle("bi-eye");
});

toggleConfirmPassword.addEventListener("click", function () {
    /* toggle the type attribute */
    const type =
        confirm_password.getAttribute("type") === "password" ? "text" : "password";
    confirm_password.setAttribute("type", type);

    /* toggle the icon */
    this.classList.toggle("bi-eye");
});



$(document).ready(function() {
    $('#signup-form').submit(function (e) {
        e.preventDefault();
        $.ajax({
            url: '/signup',
            method: 'POST',
            data: $(this).serialize(),
            dataType: 'json',
            success: function (response) {
                if (response.error) {
                    alert(response.error);
                } else if (response.success) {
                    alert(response.success);
                    window.location.href = '/login';
                }
            }
        });
    });
});
