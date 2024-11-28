package example.springsecurityjwt.auth.AuthDTO;

public record Response(
        String description,
        String token
) {
    public Response(String description, String token) {
        this.description = description;
        this.token = token;
    }

    @Override
    public String description() {
        return description;
    }

    @Override
    public String token() {
        return token;
    }
}
