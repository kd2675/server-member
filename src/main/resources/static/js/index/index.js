$(() => {
    new Index();
});

class Index {
    constructor() {
        this.init();
    }

    init() {
        $('#signInBtn').on('click', async () => {
            const redirectUrl = $('#redirectUrl').data('redirectUrl');
            const userEmail = $('#userEmail').val();
            const userPassword = $('#userPassword').val();

            try {
                const res = await axios.post(
                    "/oauth2/authorize",
                    {
                        userEmail: userEmail,
                        userPassword: userPassword
                    }
                )

                if (res.data.success) {
                    location.replace(redirectUrl + "?code=" + res.data.data.authorizationCode);
                } else {
                    console.log(res)
                }
            } catch (e) {
                console.log(e)
            }

        })
    }


}


