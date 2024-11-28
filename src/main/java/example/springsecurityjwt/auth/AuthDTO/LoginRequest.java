package example.springsecurityjwt.auth.AuthDTO;

public record LoginRequest(
        String username,
        String password
) {
    public LoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Override
    public String password() {
        return password;
    }

    @Override
    public String username() {
        return username;
    }
}
