type GoogleCredentialResponse = {
  credential: string;
  select_by: string;
};

type GoogleButtonConfiguration = {
  type?: "standard" | "icon";
  theme?: "outline" | "filled_blue" | "filled_black";
  size?: "large" | "medium" | "small";
  text?: "signin_with" | "signup_with" | "continue_with" | "signin";
  shape?: "rectangular" | "pill" | "circle" | "square";
  logo_alignment?: "left" | "center";
  width?: number;
  locale?: string;
};

interface Window {
  google?: {
    accounts: {
      id: {
        initialize(config: {
          client_id: string;
          callback(response: GoogleCredentialResponse): void;
          auto_select?: boolean;
          cancel_on_tap_outside?: boolean;
        }): void;
        renderButton(parent: HTMLElement, options: GoogleButtonConfiguration): void;
        disableAutoSelect(): void;
      };
    };
  };
}
