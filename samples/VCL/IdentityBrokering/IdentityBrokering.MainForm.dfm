object MainForm: TMainForm
  Left = 0
  Top = 0
  Caption = 
    'IAMClient4D - Identity brokering (Entra ID, Google, Facebook, Mi' +
    'crosoft, SPID, CIE, ...)'
  ClientHeight = 720
  ClientWidth = 1134
  Color = clBtnFace
  Constraints.MinHeight = 640
  Constraints.MinWidth = 960
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  ShowHint = True
  OnCloseQuery = FormCloseQuery
  OnCreate = FormCreate
  TextHeight = 15
  object MainPageControl: TPageControl
    AlignWithMargins = True
    Left = 8
    Top = 8
    Width = 1118
    Height = 704
    Margins.Left = 8
    Margins.Top = 8
    Margins.Right = 8
    Margins.Bottom = 8
    ActivePage = LoginTabSheet
    Align = alClient
    TabHeight = 30
    TabOrder = 0
    OnChange = MainPageControlChange
    object LoginTabSheet: TTabSheet
      Caption = 'Login'
      object LoginBevel: TBevel
        AlignWithMargins = True
        Left = 3
        Top = 87
        Width = 1104
        Height = 2
        Align = alTop
        Shape = bsTopLine
        ExplicitWidth = 1070
      end
      object SessionBevel: TBevel
        AlignWithMargins = True
        Left = 3
        Top = 143
        Width = 1104
        Height = 2
        Align = alTop
        Shape = bsTopLine
        ExplicitWidth = 1070
      end
      object BaseURLPanel: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 3
        Width = 1104
        Height = 22
        Align = alTop
        BevelOuter = bvNone
        ShowCaption = False
        TabOrder = 0
        object BaseURLLabel: TLabel
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 170
          Height = 16
          Align = alLeft
          AutoSize = False
          Caption = 'Keycloak base URL'
        end
        object BaseURLEdit: TEdit
          Left = 176
          Top = 0
          Width = 928
          Height = 22
          Align = alClient
          TabOrder = 0
          Text = 'http://localhost:18180/auth'
          OnChange = ConnectionEditChange
          ExplicitHeight = 23
        end
      end
      object RealmPanel: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 31
        Width = 1104
        Height = 22
        Align = alTop
        BevelOuter = bvNone
        ShowCaption = False
        TabOrder = 1
        object RealmLabel: TLabel
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 170
          Height = 16
          Align = alLeft
          AutoSize = False
          Caption = 'Realm'
        end
        object RealmEdit: TEdit
          Left = 176
          Top = 0
          Width = 928
          Height = 22
          Align = alClient
          TabOrder = 0
          Text = 'iamclient4d'
          OnChange = ConnectionEditChange
          ExplicitHeight = 23
        end
      end
      object ClientPanel: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 59
        Width = 1104
        Height = 22
        Align = alTop
        BevelOuter = bvNone
        ShowCaption = False
        TabOrder = 2
        object ClientLabel: TLabel
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 170
          Height = 16
          Align = alLeft
          AutoSize = False
          Caption = 'Client'
        end
        object ClientEdit: TEdit
          Left = 176
          Top = 0
          Width = 928
          Height = 22
          Align = alClient
          TabOrder = 0
          Text = 'iam4d-sample-app'
          ExplicitHeight = 23
        end
      end
      object LoginButtonsPanel: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 95
        Width = 1104
        Height = 42
        Align = alTop
        BevelOuter = bvNone
        ShowCaption = False
        TabOrder = 3
        object EntraLoginButton: TButton
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 126
          Height = 36
          Action = EntraLoginAction
          Align = alLeft
          TabOrder = 0
        end
        object MicrosoftLoginButton: TButton
          AlignWithMargins = True
          Left = 135
          Top = 3
          Width = 126
          Height = 36
          Action = MicrosoftLoginAction
          Align = alLeft
          TabOrder = 7
        end
        object GoogleLoginButton: TButton
          AlignWithMargins = True
          Left = 267
          Top = 3
          Width = 126
          Height = 36
          Action = GoogleLoginAction
          Align = alLeft
          TabOrder = 1
        end
        object FacebookLoginButton: TButton
          AlignWithMargins = True
          Left = 399
          Top = 3
          Width = 126
          Height = 36
          Action = FacebookLoginAction
          Align = alLeft
          TabOrder = 2
        end
        object SpidLoginButton: TButton
          AlignWithMargins = True
          Left = 531
          Top = 3
          Width = 126
          Height = 36
          Action = SpidLoginAction
          Align = alLeft
          DropDownMenu = SpidPopupMenu
          Style = bsSplitButton
          TabOrder = 3
          OnDropDownClick = SpidLoginButtonDropDownClick
        end
        object CieLoginButton: TButton
          AlignWithMargins = True
          Left = 663
          Top = 3
          Width = 120
          Height = 36
          Action = CieLoginAction
          Align = alLeft
          TabOrder = 4
        end
        object KeycloakLoginButton: TButton
          AlignWithMargins = True
          Left = 789
          Top = 3
          Width = 146
          Height = 36
          Action = KeycloakLoginAction
          Align = alLeft
          TabOrder = 5
        end
        object CancelLoginButton: TButton
          AlignWithMargins = True
          Left = 1001
          Top = 3
          Width = 100
          Height = 36
          Action = CancelLoginAction
          Align = alRight
          TabOrder = 6
        end
        object LoginActivityIndicator: TActivityIndicator
          AlignWithMargins = True
          Left = 963
          Top = 3
          Align = alRight
        end
      end
      object SessionPanel: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 151
        Width = 1104
        Height = 36
        Align = alTop
        BevelOuter = bvNone
        ShowCaption = False
        TabOrder = 4
        object SessionLabel: TLabel
          AlignWithMargins = True
          Left = 543
          Top = 3
          Width = 558
          Height = 30
          Margins.Left = 15
          Align = alClient
          AutoSize = False
          Caption = 'Not signed in'
          Font.Charset = DEFAULT_CHARSET
          Font.Color = clWindowText
          Font.Height = -12
          Font.Name = 'Segoe UI'
          Font.Style = [fsBold]
          ParentFont = False
          Layout = tlCenter
          ExplicitWidth = 524
        end
        object UserInfoButton: TButton
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 170
          Height = 30
          Action = UserInfoAction
          Align = alLeft
          TabOrder = 0
        end
        object AccessTokenButton: TButton
          AlignWithMargins = True
          Left = 179
          Top = 3
          Width = 170
          Height = 30
          Action = AccessTokenAction
          Align = alLeft
          TabOrder = 1
        end
        object LogoutButton: TButton
          AlignWithMargins = True
          Left = 355
          Top = 3
          Width = 170
          Height = 30
          Action = LogoutAction
          Align = alLeft
          TabOrder = 2
        end
      end
      object LoginMemo: TMemo
        AlignWithMargins = True
        Left = 3
        Top = 193
        Width = 1104
        Height = 468
        Align = alClient
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -12
        Font.Name = 'Consolas'
        Font.Style = []
        ParentFont = False
        ReadOnly = True
        ScrollBars = ssBoth
        TabOrder = 5
        WordWrap = False
      end
    end
    object AdminTabSheet: TTabSheet
      Caption = 'IdP administration'
      ImageIndex = 1
      object AdminStatusPanel: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 3
        Width = 1104
        Height = 36
        Align = alTop
        BevelOuter = bvNone
        ShowCaption = False
        TabOrder = 0
        object AdminStatusLabel: TLabel
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 1060
          Height = 30
          Align = alClient
          AutoSize = False
          Layout = tlCenter
          WordWrap = True
          ExplicitWidth = 1026
        end
        object AdminActivityIndicator: TActivityIndicator
          AlignWithMargins = True
          Left = 1069
          Top = 3
          Align = alRight
        end
      end
      object AdminTopPanel: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 45
        Width = 1104
        Height = 180
        Align = alTop
        BevelOuter = bvNone
        ShowCaption = False
        TabOrder = 1
        object IdPGroupBox: TGroupBox
          Left = 0
          Top = 0
          Width = 440
          Height = 180
          Align = alLeft
          Caption = 'Realm identity providers'
          TabOrder = 0
          object IdPListView: TListView
            AlignWithMargins = True
            Left = 5
            Top = 20
            Width = 430
            Height = 119
            Align = alClient
            Columns = <
              item
                Caption = 'Alias'
                Width = 100
              end
              item
                Caption = 'Type'
                Width = 75
              end
              item
                Caption = 'Display name'
                Width = 125
              end
              item
                Caption = 'Enabled'
                Width = 55
              end
              item
                Caption = 'Hidden'
                Width = 60
              end>
            HideSelection = False
            ReadOnly = True
            RowSelect = True
            TabOrder = 0
            ViewStyle = vsReport
            OnSelectItem = IdPListViewSelectItem
          end
          object IdPButtonsPanel: TPanel
            Left = 2
            Top = 142
            Width = 436
            Height = 36
            Align = alBottom
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 1
            object RefreshIdPsButton: TButton
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 140
              Height = 30
              Action = RefreshIdPsAction
              Align = alLeft
              TabOrder = 0
            end
            object DeleteIdPButton: TButton
              AlignWithMargins = True
              Left = 149
              Top = 3
              Width = 140
              Height = 30
              Action = DeleteIdPAction
              Align = alLeft
              TabOrder = 1
            end
          end
        end
        object URLGroupBox: TGroupBox
          AlignWithMargins = True
          Left = 446
          Top = 0
          Width = 658
          Height = 180
          Margins.Left = 6
          Margins.Top = 0
          Margins.Right = 0
          Margins.Bottom = 0
          Align = alClient
          Caption = 'URLs to register with the provider'
          TabOrder = 1
          object RedirectAliasPanel: TPanel
            AlignWithMargins = True
            Left = 5
            Top = 20
            Width = 648
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 0
            object RedirectAliasLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 150
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Alias'
            end
            object RedirectAliasEdit: TEdit
              Left = 156
              Top = 0
              Width = 492
              Height = 22
              Align = alClient
              ReadOnly = True
              TabOrder = 0
              ExplicitHeight = 23
            end
          end
          object RedirectURIPanel: TPanel
            AlignWithMargins = True
            Left = 5
            Top = 48
            Width = 648
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 1
            object RedirectURILabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 150
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Broker redirect URI'
            end
            object RedirectURIEdit: TEdit
              Left = 156
              Top = 0
              Width = 492
              Height = 22
              Align = alClient
              ReadOnly = True
              TabOrder = 0
              ExplicitHeight = 23
            end
          end
          object SpidSPMetadataPanel: TPanel
            AlignWithMargins = True
            Left = 5
            Top = 76
            Width = 648
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 2
            object SpidSPMetadataLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 150
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'SPID SP metadata'
            end
            object SpidSPMetadataEdit: TEdit
              Left = 156
              Top = 0
              Width = 492
              Height = 22
              Align = alClient
              ReadOnly = True
              TabOrder = 0
              ExplicitHeight = 23
            end
          end
          object CieSPMetadataPanel: TPanel
            AlignWithMargins = True
            Left = 5
            Top = 104
            Width = 648
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 3
            object CieSPMetadataLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 150
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'CIE SP metadata'
            end
            object CieSPMetadataEdit: TEdit
              Left = 156
              Top = 0
              Width = 492
              Height = 22
              Align = alClient
              ReadOnly = True
              TabOrder = 0
              ExplicitHeight = 23
            end
          end
        end
      end
      object BrokerPageControl: TPageControl
        AlignWithMargins = True
        Left = 3
        Top = 231
        Width = 1104
        Height = 210
        ActivePage = EntraTabSheet
        Align = alTop
        TabOrder = 2
        OnChange = BrokerPageControlChange
        object EntraTabSheet: TTabSheet
          Caption = 'Microsoft Entra ID'
          object EntraAliasPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 3
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 0
            object EntraAliasLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Alias'
            end
            object EntraAliasEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              Text = 'entra'
              OnChange = AliasEditChange
              ExplicitHeight = 23
            end
          end
          object EntraTenantPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 31
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 1
            object EntraTenantLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Tenant (directory ID)'
            end
            object EntraTenantEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              TextHint = 'Directory ID (GUID) or organizations'
              ExplicitHeight = 23
            end
          end
          object EntraClientIDPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 59
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 2
            object EntraClientIDLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Application (client) ID'
            end
            object EntraClientIDEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              ExplicitHeight = 23
            end
          end
          object EntraSecretPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 87
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 3
            object EntraSecretLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Client secret'
            end
            object EntraSecretEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              PasswordChar = '*'
              TabOrder = 0
              TextHint = 'Empty on an existing provider: keeps the stored secret'
              ExplicitHeight = 23
            end
          end
          object EntraPromptPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 115
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 4
            object EntraPromptLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Prompt'
            end
            object EntraPromptHintLabel: TLabel
              AlignWithMargins = True
              Left = 382
              Top = 3
              Width = 705
              Height = 16
              Margins.Left = 6
              Align = alClient
              Caption = 
                'Not set: an open Entra ID session signs in with no question, als' +
                'o after Sign out. select_account: account picker. login: credent' +
                'ials every time'
              ExplicitWidth = 730
              ExplicitHeight = 15
            end
            object EntraPromptComboBox: TComboBox
              Left = 176
              Top = 0
              Width = 200
              Height = 23
              Align = alLeft
              Style = csDropDownList
              ItemIndex = 0
              TabOrder = 0
              Text = 'Not set'
              Items.Strings = (
                'Not set'
                'select_account'
                'login'
                'consent')
            end
          end
          object EntraOptionsPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 143
            Width = 1090
            Height = 36
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 5
            object EntraHideCheckBox: TCheckBox
              AlignWithMargins = True
              Left = 179
              Top = 3
              Width = 330
              Height = 30
              Margins.Left = 179
              Align = alLeft
              Caption = 'Hide on the Keycloak login page'
              TabOrder = 0
            end
            object SaveEntraButton: TButton
              AlignWithMargins = True
              Left = 887
              Top = 3
              Width = 200
              Height = 30
              Action = SaveEntraAction
              Align = alRight
              TabOrder = 1
            end
          end
        end
        object GoogleTabSheet: TTabSheet
          Caption = 'Google'
          ImageIndex = 1
          object GoogleAliasPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 3
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 0
            object GoogleAliasLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Alias'
            end
            object GoogleAliasEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              Text = 'google'
              OnChange = AliasEditChange
              ExplicitHeight = 23
            end
          end
          object GoogleClientIDPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 31
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 1
            object GoogleClientIDLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Client ID'
            end
            object GoogleClientIDEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              TextHint = 'OAuth client ID of type Web application (Google Cloud console)'
              ExplicitHeight = 23
            end
          end
          object GoogleSecretPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 59
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 2
            object GoogleSecretLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Client secret'
            end
            object GoogleSecretEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              PasswordChar = '*'
              TabOrder = 0
              TextHint = 'Empty on an existing provider: keeps the stored secret'
              ExplicitHeight = 23
            end
          end
          object GoogleDomainsPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 87
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 3
            object GoogleDomainsLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Hosted domains'
            end
            object GoogleDomainsEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              TextHint = 
                'Optional: Google Workspace domains allowed, comma-separated (* =' +
                ' any)'
              ExplicitHeight = 23
            end
          end
          object GoogleOptionsPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 115
            Width = 1090
            Height = 36
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 4
            object GoogleHideCheckBox: TCheckBox
              AlignWithMargins = True
              Left = 179
              Top = 3
              Width = 330
              Height = 30
              Margins.Left = 179
              Align = alLeft
              Caption = 'Hide on the Keycloak login page'
              TabOrder = 0
            end
            object GoogleTrustEmailCheckBox: TCheckBox
              AlignWithMargins = True
              Left = 515
              Top = 3
              Width = 200
              Height = 30
              Align = alLeft
              Caption = 'Trust email'
              TabOrder = 1
            end
            object SaveGoogleButton: TButton
              AlignWithMargins = True
              Left = 887
              Top = 3
              Width = 200
              Height = 30
              Action = SaveGoogleAction
              Align = alRight
              TabOrder = 2
            end
          end
        end
        object FacebookTabSheet: TTabSheet
          Caption = 'Facebook'
          ImageIndex = 2
          object FacebookAliasPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 3
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 0
            object FacebookAliasLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Alias'
            end
            object FacebookAliasEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              Text = 'facebook'
              OnChange = AliasEditChange
              ExplicitHeight = 23
            end
          end
          object FacebookAppIDPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 31
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 1
            object FacebookAppIDLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'App ID'
            end
            object FacebookAppIDEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              TextHint = 'Meta app with the Facebook Login product'
              ExplicitHeight = 23
            end
          end
          object FacebookSecretPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 59
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 2
            object FacebookSecretLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'App secret'
            end
            object FacebookSecretEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              PasswordChar = '*'
              TabOrder = 0
              TextHint = 'Empty on an existing provider: keeps the stored secret'
              ExplicitHeight = 23
            end
          end
          object FacebookOptionsPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 87
            Width = 1090
            Height = 36
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 3
            object FacebookHideCheckBox: TCheckBox
              AlignWithMargins = True
              Left = 179
              Top = 3
              Width = 330
              Height = 30
              Margins.Left = 179
              Align = alLeft
              Caption = 'Hide on the Keycloak login page'
              TabOrder = 0
            end
            object SaveFacebookButton: TButton
              AlignWithMargins = True
              Left = 887
              Top = 3
              Width = 200
              Height = 30
              Action = SaveFacebookAction
              Align = alRight
              TabOrder = 1
            end
          end
        end
        object OidcTabSheet: TTabSheet
          Caption = 'Generic OIDC'
          ImageIndex = 3
          object OidcAliasPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 3
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 0
            object OidcAliasLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Alias'
            end
            object OidcAliasEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              Text = 'oidc'
              OnChange = AliasEditChange
              ExplicitHeight = 23
            end
          end
          object OidcDiscoveryPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 31
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 1
            object OidcDiscoveryLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Discovery URL'
            end
            object OidcDiscoveryEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              TextHint = 
                'https://idp.example.com/.well-known/openid-configuration (read b' +
                'y Keycloak)'
              ExplicitHeight = 23
            end
          end
          object OidcClientIDPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 59
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 2
            object OidcClientIDLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Client ID'
            end
            object OidcClientIDEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              TextHint = 'Confidential client registered at the provider'
              ExplicitHeight = 23
            end
          end
          object OidcSecretPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 87
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 3
            object OidcSecretLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Client secret'
            end
            object OidcSecretEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              PasswordChar = '*'
              TabOrder = 0
              TextHint = 'Empty on an existing provider: keeps the stored secret'
              ExplicitHeight = 23
            end
          end
          object OidcOptionsPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 115
            Width = 1090
            Height = 36
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 4
            object OidcLoginLabel: TLabel
              AlignWithMargins = True
              Left = 179
              Top = 3
              Width = 600
              Height = 30
              Margins.Left = 179
              Align = alLeft
              AutoSize = False
              Caption = 
                'No login button: sign in from the Keycloak login page, or with t' +
                'he alias as kc_idp_hint'
              Layout = tlCenter
            end
            object SaveOidcButton: TButton
              AlignWithMargins = True
              Left = 887
              Top = 3
              Width = 200
              Height = 30
              Action = SaveOidcAction
              Align = alRight
              TabOrder = 0
            end
          end
        end
        object OtherTabSheet: TTabSheet
          Caption = 'Other providers'
          ImageIndex = 7
          object OtherLeftPanel: TPanel
            Left = 0
            Top = 0
            Width = 520
            Height = 180
            Align = alLeft
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 0
            ExplicitHeight = 175
            object OtherTypePanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 514
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 0
              object OtherTypeLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 130
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Provider type'
              end
              object OtherTypeComboBox: TComboBox
                Left = 136
                Top = 0
                Width = 378
                Height = 23
                Align = alClient
                Style = csDropDownList
                TabOrder = 0
                OnChange = OtherTypeComboBoxChange
                Items.Strings = (
                  'Microsoft account (microsoft)'
                  'LinkedIn (linkedin-openid-connect)'
                  'GitHub (github)'
                  'GitLab.com (gitlab)'
                  'Any OAuth 2.0 provider (oauth2)')
              end
            end
            object OtherAliasPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 31
              Width = 514
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 1
              object OtherAliasLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 130
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Alias'
              end
              object OtherAliasEdit: TEdit
                Left = 136
                Top = 0
                Width = 378
                Height = 22
                Align = alClient
                TabOrder = 0
                Text = 'microsoft'
                OnChange = AliasEditChange
                ExplicitHeight = 23
              end
            end
            object OtherClientIDPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 59
              Width = 514
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 2
              object OtherClientIDLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 130
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Client ID'
              end
              object OtherClientIDEdit: TEdit
                Left = 136
                Top = 0
                Width = 378
                Height = 22
                Align = alClient
                TabOrder = 0
                TextHint = 'Client ID registered at the provider'
                ExplicitHeight = 23
              end
            end
            object OtherSecretPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 87
              Width = 514
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 3
              object OtherSecretLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 130
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Client secret'
              end
              object OtherSecretEdit: TEdit
                Left = 136
                Top = 0
                Width = 378
                Height = 22
                Align = alClient
                PasswordChar = '*'
                TabOrder = 0
                TextHint = 'Empty on an existing provider: keeps the stored secret'
                ExplicitHeight = 23
              end
            end
            object OtherOptionsPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 115
              Width = 514
              Height = 36
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 4
              object OtherHideCheckBox: TCheckBox
                AlignWithMargins = True
                Left = 139
                Top = 3
                Width = 130
                Height = 30
                Margins.Left = 139
                Align = alLeft
                Caption = 'Hide on login page'
                TabOrder = 0
              end
              object OtherTrustEmailCheckBox: TCheckBox
                AlignWithMargins = True
                Left = 275
                Top = 3
                Width = 90
                Height = 30
                Align = alLeft
                Caption = 'Trust email'
                TabOrder = 1
              end
              object SaveOtherButton: TButton
                AlignWithMargins = True
                Left = 371
                Top = 3
                Width = 140
                Height = 30
                Action = SaveOtherAction
                Align = alRight
                TabOrder = 2
              end
            end
          end
          object OtherRightPanel: TPanel
            Left = 520
            Top = 0
            Width = 576
            Height = 180
            Align = alClient
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 1
            ExplicitHeight = 175
            object OtherNoteLabel: TLabel
              AlignWithMargins = True
              Left = 9
              Top = 227
              Width = 564
              Height = 60
              Margins.Left = 9
              Align = alTop
              AutoSize = False
              WordWrap = True
              ExplicitLeft = 3
              ExplicitWidth = 528
            end
            object OtherTenantPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 570
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 0
              object OtherTenantLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 130
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Tenant'
              end
              object OtherTenantEdit: TEdit
                Left = 136
                Top = 0
                Width = 434
                Height = 22
                Align = alClient
                TabOrder = 0
                Text = 'consumers'
                TextHint = 
                  'consumers (personal accounts), common, organizations or a direct' +
                  'ory ID'
                ExplicitHeight = 23
              end
            end
            object OtherBaseURLPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 31
              Width = 570
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 1
              object OtherBaseURLLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 130
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Enterprise web URL'
              end
              object OtherBaseURLEdit: TEdit
                Left = 136
                Top = 0
                Width = 434
                Height = 22
                Align = alClient
                TabOrder = 0
                TextHint = 
                  'Optional: GitHub Enterprise Server, e.g. https://github.example.' +
                  'com'
                ExplicitHeight = 23
              end
            end
            object OtherApiURLPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 59
              Width = 570
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 2
              object OtherApiURLLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 130
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Enterprise API URL'
              end
              object OtherApiURLEdit: TEdit
                Left = 136
                Top = 0
                Width = 434
                Height = 22
                Align = alClient
                TabOrder = 0
                TextHint = 'With the web URL, e.g. https://github.example.com/api/v3'
                ExplicitHeight = 23
              end
            end
            object OtherAuthURLPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 87
              Width = 570
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 3
              object OtherAuthURLLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 130
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Authorization URL'
              end
              object OtherAuthURLEdit: TEdit
                Left = 136
                Top = 0
                Width = 434
                Height = 22
                Align = alClient
                TabOrder = 0
                TextHint = 'Authorization endpoint of the provider'
                ExplicitHeight = 23
              end
            end
            object OtherTokenURLPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 115
              Width = 570
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 4
              object OtherTokenURLLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 130
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Token URL'
              end
              object OtherTokenURLEdit: TEdit
                Left = 136
                Top = 0
                Width = 434
                Height = 22
                Align = alClient
                TabOrder = 0
                TextHint = 'Token endpoint of the provider'
                ExplicitHeight = 23
              end
            end
            object OtherUserInfoURLPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 143
              Width = 570
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 5
              object OtherUserInfoURLLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 130
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'User info URL'
              end
              object OtherUserInfoURLEdit: TEdit
                Left = 136
                Top = 0
                Width = 434
                Height = 22
                Align = alClient
                TabOrder = 0
                TextHint = 'JSON profile read with the access token'
                ExplicitHeight = 23
              end
            end
            object OtherScopesPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 171
              Width = 570
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 6
              object OtherScopesLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 130
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Scopes'
              end
              object OtherScopesEdit: TEdit
                Left = 136
                Top = 0
                Width = 434
                Height = 22
                Align = alClient
                TabOrder = 0
                TextHint = 'Space-separated, e.g. read:user'
                ExplicitHeight = 23
              end
            end
            object OtherClaimsPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 199
              Width = 570
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 7
              object OtherClaimsLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 130
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Profile fields'
              end
              object OtherClaimsEdit: TEdit
                Left = 136
                Top = 0
                Width = 434
                Height = 22
                Align = alClient
                TabOrder = 0
                TextHint = 'User ID, username, email fields, e.g. id,login,email'
                ExplicitHeight = 23
              end
            end
          end
        end
        object SpidTabSheet: TTabSheet
          Caption = 'SPID'
          ImageIndex = 4
          object SpidProviderPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 3
            Width = 1090
            Height = 26
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 0
            object SpidProviderLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 20
              Align = alLeft
              AutoSize = False
              Caption = 'SPID identity provider'
            end
            object LoadRegistryButton: TButton
              AlignWithMargins = True
              Left = 920
              Top = 0
              Width = 170
              Height = 26
              Margins.Left = 6
              Margins.Top = 0
              Margins.Right = 0
              Margins.Bottom = 0
              Action = LoadSpidRegistryAction
              Align = alRight
              TabOrder = 1
            end
            object SpidProviderComboBox: TComboBox
              Left = 176
              Top = 0
              Width = 738
              Height = 23
              Align = alClient
              Style = csDropDownList
              TabOrder = 0
              OnChange = SpidProviderComboBoxChange
            end
          end
          object SpidAliasPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 35
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 1
            object SpidAliasLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Alias'
            end
            object SpidAliasEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              OnChange = AliasEditChange
              ExplicitHeight = 23
            end
          end
          object SpidMetadataPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 63
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 2
            object SpidMetadataLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Identity provider metadata'
            end
            object SpidMetadataEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              ReadOnly = True
              TabOrder = 0
              ExplicitHeight = 23
            end
          end
          object SpidLevelPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 91
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 3
            object SpidLevelLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Level'
            end
            object SpidLevelComboBox: TComboBox
              Left = 176
              Top = 0
              Width = 200
              Height = 23
              Align = alLeft
              Style = csDropDownList
              ItemIndex = 1
              TabOrder = 0
              Text = 'SpidL2'
              Items.Strings = (
                'SpidL1'
                'SpidL2'
                'SpidL3')
            end
          end
          object SpidOptionsPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 119
            Width = 1090
            Height = 36
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 4
            object SpidHideCheckBox: TCheckBox
              AlignWithMargins = True
              Left = 179
              Top = 3
              Width = 330
              Height = 30
              Margins.Left = 179
              Align = alLeft
              Caption = 'Hide on the Keycloak login page'
              Checked = True
              State = cbChecked
              TabOrder = 0
            end
            object SaveSpidButton: TButton
              AlignWithMargins = True
              Left = 887
              Top = 3
              Width = 200
              Height = 30
              Action = SaveSpidAction
              Align = alRight
              TabOrder = 1
            end
          end
        end
        object CieTabSheet: TTabSheet
          Caption = 'CIE ID'
          ImageIndex = 5
          object CieEnvironmentPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 3
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 0
            object CieEnvironmentLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Environment'
            end
            object CieEnvironmentComboBox: TComboBox
              Left = 176
              Top = 0
              Width = 200
              Height = 23
              Align = alLeft
              Style = csDropDownList
              ItemIndex = 2
              TabOrder = 0
              Text = 'Local test (CIE simulator)'
              OnChange = CieEnvironmentComboBoxChange
              Items.Strings = (
                'Production'
                'Pre-production'
                'Local test (CIE simulator)')
            end
          end
          object CieAliasPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 31
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 1
            object CieAliasLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Alias'
            end
            object CieAliasEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              TabOrder = 0
              Text = 'cie'
              OnChange = AliasEditChange
              ExplicitHeight = 23
            end
          end
          object CieMetadataPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 59
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 2
            object CieMetadataLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Identity server metadata'
            end
            object CieMetadataEdit: TEdit
              Left = 176
              Top = 0
              Width = 914
              Height = 22
              Align = alClient
              ReadOnly = True
              TabOrder = 0
              ExplicitHeight = 23
            end
          end
          object CieLevelPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 87
            Width = 1090
            Height = 22
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 3
            object CieLevelLabel: TLabel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 170
              Height = 16
              Align = alLeft
              AutoSize = False
              Caption = 'Level'
            end
            object CieLevelComboBox: TComboBox
              Left = 176
              Top = 0
              Width = 200
              Height = 23
              Align = alLeft
              Style = csDropDownList
              ItemIndex = 1
              TabOrder = 0
              Text = 'SpidL2'
              Items.Strings = (
                'SpidL1'
                'SpidL2'
                'SpidL3')
            end
          end
          object CieOptionsPanel: TPanel
            AlignWithMargins = True
            Left = 3
            Top = 115
            Width = 1090
            Height = 36
            Align = alTop
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 4
            object CieHideCheckBox: TCheckBox
              AlignWithMargins = True
              Left = 179
              Top = 3
              Width = 330
              Height = 30
              Margins.Left = 179
              Align = alLeft
              Caption = 'Hide on the Keycloak login page'
              TabOrder = 0
            end
            object SaveCieButton: TButton
              AlignWithMargins = True
              Left = 887
              Top = 3
              Width = 200
              Height = 30
              Action = SaveCieAction
              Align = alRight
              TabOrder = 1
            end
          end
        end
        object ServiceProviderTabSheet: TTabSheet
          Caption = 'Service provider (SPID and CIE)'
          ImageIndex = 6
          object OrganizationPanel: TPanel
            Left = 0
            Top = 0
            Width = 480
            Height = 180
            Align = alLeft
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 0
            ExplicitHeight = 175
            object OrgNamePanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 474
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 0
              object OrgNameLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 140
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Organization'
              end
              object OrgNameEdit: TEdit
                Left = 146
                Top = 0
                Width = 328
                Height = 22
                Align = alClient
                TabOrder = 0
                Text = 'Comune di Esempio'
                ExplicitHeight = 23
              end
            end
            object OrgDisplayNamePanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 31
              Width = 474
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 1
              object OrgDisplayNameLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 140
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Display name'
              end
              object OrgDisplayNameEdit: TEdit
                Left = 146
                Top = 0
                Width = 328
                Height = 22
                Align = alClient
                TabOrder = 0
                Text = 'Comune di Esempio'
                ExplicitHeight = 23
              end
            end
            object OrgURLPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 59
              Width = 474
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 2
              object OrgURLLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 140
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Website'
              end
              object OrgURLEdit: TEdit
                Left = 146
                Top = 0
                Width = 328
                Height = 22
                Align = alClient
                TabOrder = 0
                Text = 'https://www.comune.esempio.it'
                ExplicitHeight = 23
              end
            end
            object SPTypePanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 87
              Width = 474
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 3
              object SPTypeLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 140
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Provider type'
              end
              object SPTypeComboBox: TComboBox
                Left = 146
                Top = 0
                Width = 328
                Height = 23
                Align = alClient
                Style = csDropDownList
                ItemIndex = 0
                TabOrder = 0
                Text = 'Public administration'
                OnChange = SPTypeComboBoxChange
                Items.Strings = (
                  'Public administration'
                  'Private')
              end
            end
            object ServiceNamePanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 115
              Width = 474
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 4
              object ServiceNameLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 140
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Service name'
              end
              object ServiceNameEdit: TEdit
                Left = 146
                Top = 0
                Width = 328
                Height = 22
                Hint = 
                  'ServiceName of AttributeConsumingService 1 in the SP metadata (S' +
                  'PID and CIE)'
                Align = alClient
                TabOrder = 0
                Text = 'Servizio di esempio'
                ExplicitHeight = 23
              end
            end
          end
          object ContactsPanel: TPanel
            AlignWithMargins = True
            Left = 486
            Top = 0
            Width = 610
            Height = 180
            Margins.Left = 6
            Margins.Top = 0
            Margins.Right = 0
            Margins.Bottom = 0
            Align = alClient
            BevelOuter = bvNone
            ShowCaption = False
            TabOrder = 1
            ExplicitHeight = 175
            object IpaCodePanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 604
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 0
              object IpaCodeLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 140
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'IPA code'
              end
              object IpaCodeEdit: TEdit
                Left = 146
                Top = 0
                Width = 458
                Height = 22
                Align = alClient
                TabOrder = 0
                Text = 'c_x000'
                ExplicitHeight = 23
              end
            end
            object IpaCategoryPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 31
              Width = 604
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 1
              object IpaCategoryLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 140
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'IPA category (CIE)'
              end
              object IpaCategoryEdit: TEdit
                Left = 146
                Top = 0
                Width = 458
                Height = 22
                Align = alClient
                TabOrder = 0
                Text = 'L6'
                ExplicitHeight = 23
              end
            end
            object VatNumberPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 59
              Width = 604
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 2
              object VatNumberLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 140
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'VAT number'
              end
              object VatNumberEdit: TEdit
                Left = 146
                Top = 0
                Width = 458
                Height = 22
                Align = alClient
                TabOrder = 0
                TextHint = 'E.g. IT12345678901'
                ExplicitHeight = 23
              end
            end
            object FiscalCodePanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 87
              Width = 604
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 3
              object FiscalCodeLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 140
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Fiscal code'
              end
              object FiscalCodeEdit: TEdit
                Left = 146
                Top = 0
                Width = 458
                Height = 22
                Align = alClient
                TabOrder = 0
                ExplicitHeight = 23
              end
            end
            object EmailPanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 115
              Width = 604
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 4
              object EmailLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 140
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Email'
              end
              object EmailEdit: TEdit
                Left = 146
                Top = 0
                Width = 458
                Height = 22
                Align = alClient
                TabOrder = 0
                Text = 'protocollo@comune.esempio.it'
                ExplicitHeight = 23
              end
            end
            object PhonePanel: TPanel
              AlignWithMargins = True
              Left = 3
              Top = 143
              Width = 604
              Height = 22
              Align = alTop
              BevelOuter = bvNone
              ShowCaption = False
              TabOrder = 5
              object PhoneLabel: TLabel
                AlignWithMargins = True
                Left = 3
                Top = 3
                Width = 140
                Height = 16
                Align = alLeft
                AutoSize = False
                Caption = 'Phone'
              end
              object PhoneEdit: TEdit
                Left = 146
                Top = 0
                Width = 458
                Height = 22
                Align = alClient
                TabOrder = 0
                ExplicitHeight = 23
              end
            end
          end
        end
      end
      object AdminMemo: TMemo
        AlignWithMargins = True
        Left = 3
        Top = 447
        Width = 1104
        Height = 214
        Align = alClient
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -12
        Font.Name = 'Consolas'
        Font.Style = []
        ParentFont = False
        ReadOnly = True
        ScrollBars = ssBoth
        TabOrder = 3
        WordWrap = False
        ExplicitTop = 442
        ExplicitHeight = 219
      end
    end
  end
  object MainActionList: TActionList
    OnUpdate = MainActionListUpdate
    Left = 40
    Top = 648
    object EntraLoginAction: TAction
      Category = 'Accesso'
      Caption = 'Sign in with Entra ID'
      Hint = 
        'Direct login to Microsoft Entra ID, work accounts (kc_idp_hint=e' +
        'ntra)'
      OnExecute = EntraLoginActionExecute
    end
    object MicrosoftLoginAction: TAction
      Category = 'Accesso'
      Caption = 'Microsoft account'
      Hint = 
        'Direct login with a personal Microsoft account (kc_idp_hint=micr' +
        'osoft)'
      OnExecute = MicrosoftLoginActionExecute
    end
    object GoogleLoginAction: TAction
      Category = 'Accesso'
      Caption = 'Sign in with Google'
      Hint = 'Direct login to Google (kc_idp_hint=google)'
      OnExecute = GoogleLoginActionExecute
    end
    object FacebookLoginAction: TAction
      Category = 'Accesso'
      Caption = 'Sign in with Facebook'
      Hint = 'Direct login to Facebook (kc_idp_hint=facebook)'
      OnExecute = FacebookLoginActionExecute
    end
    object SpidLoginAction: TAction
      Category = 'Accesso'
      Caption = 'Sign in with SPID'
      Hint = 'Pick the SPID identity provider: kc_idp_hint=spid-<name>'
      OnExecute = SpidLoginActionExecute
    end
    object CieLoginAction: TAction
      Category = 'Accesso'
      Caption = 'Sign in with CIE'
      Hint = 'Direct login to CIE ID (kc_idp_hint=cie)'
      OnExecute = CieLoginActionExecute
    end
    object KeycloakLoginAction: TAction
      Category = 'Accesso'
      Caption = 'Keycloak login page'
      Hint = 'No kc_idp_hint: the Keycloak login page with every provider'
      OnExecute = KeycloakLoginActionExecute
    end
    object CancelLoginAction: TAction
      Category = 'Accesso'
      Caption = 'Cancel login'
      Hint = 'Stops waiting for the browser'
      OnExecute = CancelLoginActionExecute
    end
    object UserInfoAction: TAction
      Category = 'Accesso'
      Caption = 'User info'
      OnExecute = UserInfoActionExecute
    end
    object AccessTokenAction: TAction
      Category = 'Accesso'
      Caption = 'Access token'
      OnExecute = AccessTokenActionExecute
    end
    object LogoutAction: TAction
      Category = 'Accesso'
      Caption = 'Sign out'
      OnExecute = LogoutActionExecute
    end
    object RefreshIdPsAction: TAction
      Category = 'Amministrazione'
      Caption = 'Refresh list'
      OnExecute = RefreshIdPsActionExecute
    end
    object DeleteIdPAction: TAction
      Category = 'Amministrazione'
      Caption = 'Delete'
      OnExecute = DeleteIdPActionExecute
    end
    object SaveEntraAction: TAction
      Category = 'Amministrazione'
      Caption = 'Save Entra ID'
      OnExecute = SaveEntraActionExecute
    end
    object SaveGoogleAction: TAction
      Category = 'Amministrazione'
      Caption = 'Save Google'
      OnExecute = SaveGoogleActionExecute
    end
    object SaveFacebookAction: TAction
      Category = 'Amministrazione'
      Caption = 'Save Facebook'
      OnExecute = SaveFacebookActionExecute
    end
    object SaveOidcAction: TAction
      Category = 'Amministrazione'
      Caption = 'Import discovery and save'
      OnExecute = SaveOidcActionExecute
    end
    object SaveOtherAction: TAction
      Category = 'Amministrazione'
      Caption = 'Save'
      OnExecute = SaveOtherActionExecute
    end
    object LoadSpidRegistryAction: TAction
      Category = 'Amministrazione'
      Caption = 'Load AgID registry'
      OnExecute = LoadSpidRegistryActionExecute
    end
    object SaveSpidAction: TAction
      Category = 'Amministrazione'
      Caption = 'Import metadata and save'
      OnExecute = SaveSpidActionExecute
    end
    object SaveCieAction: TAction
      Category = 'Amministrazione'
      Caption = 'Import metadata and save'
      OnExecute = SaveCieActionExecute
    end
  end
  object SpidPopupMenu: TPopupMenu
    Left = 144
    Top = 648
  end
end
