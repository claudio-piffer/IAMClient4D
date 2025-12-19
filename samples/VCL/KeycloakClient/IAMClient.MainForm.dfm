object MainForm: TMainForm
  Left = 0
  Top = 0
  Caption = 'Keycloak client test'
  ClientHeight = 571
  ClientWidth = 974
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  TextHeight = 15
  object MainPageControl: TPageControl
    AlignWithMargins = True
    Left = 8
    Top = 8
    Width = 958
    Height = 555
    Margins.Left = 8
    Margins.Top = 8
    Margins.Right = 8
    Margins.Bottom = 8
    ActivePage = CCTabSheet
    Align = alClient
    TabHeight = 38
    TabOrder = 0
    object PKCETabSheet: TTabSheet
      Caption = '.:: Authorization Code Flow with PKCE ::.'
      object Bevel1: TBevel
        AlignWithMargins = True
        Left = 3
        Top = 87
        Width = 944
        Height = 2
        Align = alTop
        Shape = bsTopLine
        ExplicitLeft = 200
        ExplicitTop = 161
        ExplicitWidth = 50
      end
      object Bevel2: TBevel
        AlignWithMargins = True
        Left = 3
        Top = 137
        Width = 944
        Height = 2
        Align = alTop
        Shape = bsTopLine
        ExplicitLeft = 200
        ExplicitTop = 161
        ExplicitWidth = 50
      end
      object Bevel3: TBevel
        AlignWithMargins = True
        Left = 3
        Top = 173
        Width = 944
        Height = 2
        Align = alTop
        Shape = bsTopLine
        ExplicitLeft = 200
        ExplicitTop = 161
        ExplicitWidth = 50
      end
      object Panel1: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 3
        Width = 944
        Height = 22
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel1'
        ShowCaption = False
        TabOrder = 0
        object PKCEBaseURLLabel: TLabel
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 120
          Height = 16
          Align = alLeft
          AutoSize = False
          Caption = 'Keycloak base url'
        end
        object PKCEBaseURLEdit: TEdit
          Left = 126
          Top = 0
          Width = 818
          Height = 22
          Align = alClient
          TabOrder = 0
          Text = 'https://192.168.0.24:28443/auth'
          ExplicitHeight = 23
        end
      end
      object Panel3: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 31
        Width = 944
        Height = 22
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel1'
        ShowCaption = False
        TabOrder = 1
        object PKCERealmLabel: TLabel
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 120
          Height = 16
          Align = alLeft
          AutoSize = False
          Caption = 'Realm'
        end
        object PKCERealmEdit: TEdit
          Left = 126
          Top = 0
          Width = 818
          Height = 22
          Align = alClient
          TabOrder = 0
          Text = 'iamclient4d'
          ExplicitHeight = 23
        end
      end
      object Panel4: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 59
        Width = 944
        Height = 22
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel1'
        ShowCaption = False
        TabOrder = 2
        object PKCEClientLabel: TLabel
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 120
          Height = 16
          Align = alLeft
          AutoSize = False
          Caption = 'Client'
        end
        object PKCEClientEdit: TEdit
          Left = 126
          Top = 0
          Width = 818
          Height = 22
          Align = alClient
          TabOrder = 0
          Text = 'demo_public'
          ExplicitHeight = 23
        end
      end
      object Panel2: TPanel
        AlignWithMargins = True
        Left = 8
        Top = 92
        Width = 934
        Height = 42
        Margins.Left = 8
        Margins.Top = 0
        Margins.Right = 8
        Margins.Bottom = 0
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel2'
        ShowCaption = False
        TabOrder = 3
        object LoginButton: TButton
          AlignWithMargins = True
          Left = 367
          Top = 3
          Width = 100
          Height = 36
          Action = LoginAction
          Align = alRight
          TabOrder = 0
        end
        object UserInfoButton: TButton
          AlignWithMargins = True
          Left = 831
          Top = 3
          Width = 100
          Height = 36
          Action = UserInfoAction
          Align = alRight
          TabOrder = 1
        end
        object Button1: TButton
          AlignWithMargins = True
          Left = 473
          Top = 3
          Width = 100
          Height = 36
          Action = LogoutAction
          Align = alRight
          TabOrder = 2
        end
        object VerifyJWTButton: TButton
          AlignWithMargins = True
          Left = 725
          Top = 3
          Width = 100
          Height = 36
          Action = VerifyJWTAction
          Align = alRight
          TabOrder = 3
        end
        object Button3: TButton
          AlignWithMargins = True
          Left = 579
          Top = 3
          Width = 140
          Height = 36
          Action = AccessTokenAsyncAction
          Align = alRight
          TabOrder = 4
          WordWrap = True
        end
        object PKCEActivityIndicator: TActivityIndicator
          AlignWithMargins = True
          Left = 3
          Top = 3
          Align = alLeft
        end
      end
      object Panel6: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 145
        Width = 944
        Height = 22
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel1'
        ShowCaption = False
        TabOrder = 4
        object LoginURLLabel: TLabel
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 120
          Height = 16
          Align = alLeft
          AutoSize = False
          Caption = 'Login URL'
        end
        object LoginURLEdit: TEdit
          Left = 126
          Top = 0
          Width = 818
          Height = 22
          Align = alClient
          ReadOnly = True
          TabOrder = 0
          ExplicitHeight = 23
        end
      end
      object PKCEMemo: TMemo
        AlignWithMargins = True
        Left = 3
        Top = 181
        Width = 944
        Height = 323
        Align = alClient
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -13
        Font.Name = 'Courier New'
        Font.Style = []
        ParentFont = False
        ReadOnly = True
        ScrollBars = ssVertical
        TabOrder = 5
      end
    end
    object UserManagementTabSheet: TTabSheet
      Caption = '.:: User management ::.'
      ImageIndex = 2
      object Panel12: TPanel
        AlignWithMargins = True
        Left = 8
        Top = 42
        Width = 934
        Height = 42
        Margins.Left = 8
        Margins.Top = 0
        Margins.Right = 8
        Margins.Bottom = 0
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel2'
        ShowCaption = False
        TabOrder = 0
        object Button4: TButton
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 150
          Height = 36
          Action = CreateMultipleUsersAction
          Align = alLeft
          TabOrder = 0
          WordWrap = True
        end
        object Button8: TButton
          AlignWithMargins = True
          Left = 159
          Top = 3
          Width = 150
          Height = 36
          Action = UpdateMultipleUsersAction
          Align = alLeft
          TabOrder = 1
        end
        object Button9: TButton
          AlignWithMargins = True
          Left = 783
          Top = 3
          Width = 150
          Height = 36
          Action = DeleteMultipleUserAction
          Align = alLeft
          TabOrder = 2
        end
        object Button10: TButton
          AlignWithMargins = True
          Left = 315
          Top = 3
          Width = 150
          Height = 36
          Action = ChangePasswordsAction
          Align = alLeft
          TabOrder = 3
        end
        object Button11: TButton
          AlignWithMargins = True
          Left = 627
          Top = 3
          Width = 150
          Height = 36
          Action = AssignRolesUsersAction
          Align = alLeft
          TabOrder = 4
        end
        object Button12: TButton
          AlignWithMargins = True
          Left = 471
          Top = 3
          Width = 150
          Height = 36
          Action = ClientsRealmAction
          Align = alLeft
          TabOrder = 5
        end
      end
      object Memo3: TMemo
        AlignWithMargins = True
        Left = 3
        Top = 129
        Width = 944
        Height = 375
        Align = alClient
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -13
        Font.Name = 'Courier New'
        Font.Style = []
        ParentFont = False
        ReadOnly = True
        ScrollBars = ssVertical
        TabOrder = 1
      end
      object Panel5: TPanel
        AlignWithMargins = True
        Left = 8
        Top = 0
        Width = 934
        Height = 42
        Margins.Left = 8
        Margins.Top = 0
        Margins.Right = 8
        Margins.Bottom = 0
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel2'
        ShowCaption = False
        TabOrder = 2
        object Button13: TButton
          AlignWithMargins = True
          Left = 159
          Top = 3
          Width = 150
          Height = 36
          Action = UserSampleCreateUserAction
          Align = alLeft
          TabOrder = 0
        end
        object Button14: TButton
          AlignWithMargins = True
          Left = 315
          Top = 3
          Width = 150
          Height = 36
          Action = GetUserAction
          Align = alLeft
          TabOrder = 1
        end
        object Button15: TButton
          AlignWithMargins = True
          Left = 783
          Top = 3
          Width = 150
          Height = 36
          Action = DeleteUserAction
          Align = alLeft
          TabOrder = 2
        end
        object Button16: TButton
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 150
          Height = 36
          Action = ConnectToUserManagerAction
          Align = alLeft
          TabOrder = 3
          WordWrap = True
        end
        object Button17: TButton
          AlignWithMargins = True
          Left = 627
          Top = 3
          Width = 150
          Height = 36
          Action = UpdateUserAction
          Align = alLeft
          TabOrder = 4
        end
        object Button18: TButton
          AlignWithMargins = True
          Left = 471
          Top = 3
          Width = 150
          Height = 36
          Action = UserByUserNameAction
          Align = alLeft
          TabOrder = 5
        end
      end
      object Panel13: TPanel
        AlignWithMargins = True
        Left = 8
        Top = 84
        Width = 934
        Height = 42
        Margins.Left = 8
        Margins.Top = 0
        Margins.Right = 8
        Margins.Bottom = 0
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel2'
        ShowCaption = False
        TabOrder = 3
        object Button19: TButton
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 150
          Height = 36
          Action = ChangePasswordAction
          Align = alLeft
          TabOrder = 0
          WordWrap = True
        end
        object Button20: TButton
          AlignWithMargins = True
          Left = 159
          Top = 3
          Width = 150
          Height = 36
          Action = RealmRoleAction
          Align = alLeft
          TabOrder = 1
        end
        object Button21: TButton
          AlignWithMargins = True
          Left = 315
          Top = 3
          Width = 150
          Height = 36
          Action = UserRolesAction
          Align = alLeft
          TabOrder = 2
        end
        object Button22: TButton
          AlignWithMargins = True
          Left = 471
          Top = 3
          Width = 150
          Height = 36
          Action = SearchUserAction
          Align = alLeft
          TabOrder = 3
        end
        object Button24: TButton
          AlignWithMargins = True
          Left = 627
          Top = 3
          Width = 150
          Height = 36
          Action = UserFederatedAction
          Align = alLeft
          TabOrder = 4
        end
      end
    end
    object CCTabSheet: TTabSheet
      Caption = '.:: Client Credentials Flow ::.'
      ImageIndex = 1
      object Bevel4: TBevel
        AlignWithMargins = True
        Left = 3
        Top = 115
        Width = 944
        Height = 2
        Align = alTop
        Shape = bsTopLine
        ExplicitLeft = 6
        ExplicitTop = 11
        ExplicitWidth = 789
      end
      object Bevel5: TBevel
        AlignWithMargins = True
        Left = 3
        Top = 165
        Width = 944
        Height = 2
        Align = alTop
        Shape = bsTopLine
        ExplicitLeft = 200
        ExplicitTop = 161
        ExplicitWidth = 50
      end
      object CCMemo: TMemo
        AlignWithMargins = True
        Left = 3
        Top = 173
        Width = 944
        Height = 331
        Align = alClient
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -13
        Font.Name = 'Courier New'
        Font.Style = []
        ParentFont = False
        ReadOnly = True
        ScrollBars = ssVertical
        TabOrder = 0
      end
      object Panel7: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 3
        Width = 944
        Height = 22
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel1'
        ShowCaption = False
        TabOrder = 1
        object Label5: TLabel
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 120
          Height = 16
          Align = alLeft
          AutoSize = False
          Caption = 'Keycloak base url'
        end
        object CCBaseURLEdit: TEdit
          Left = 126
          Top = 0
          Width = 818
          Height = 22
          Align = alClient
          TabOrder = 0
          Text = 'https://192.168.0.24:28443/auth'
          ExplicitHeight = 23
        end
      end
      object Panel8: TPanel
        AlignWithMargins = True
        Left = 8
        Top = 120
        Width = 934
        Height = 42
        Margins.Left = 8
        Margins.Top = 0
        Margins.Right = 8
        Margins.Bottom = 0
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel2'
        ShowCaption = False
        TabOrder = 2
        object Button2: TButton
          AlignWithMargins = True
          Left = 473
          Top = 3
          Width = 100
          Height = 36
          Action = LoginCredentialAccess
          Align = alRight
          TabOrder = 0
        end
        object Button5: TButton
          AlignWithMargins = True
          Left = 579
          Top = 3
          Width = 100
          Height = 36
          Action = CCLogoutAction
          Align = alRight
          TabOrder = 1
        end
        object Button6: TButton
          AlignWithMargins = True
          Left = 831
          Top = 3
          Width = 100
          Height = 36
          Action = CCVerifyJWTAction
          Align = alRight
          TabOrder = 2
        end
        object Button7: TButton
          AlignWithMargins = True
          Left = 685
          Top = 3
          Width = 140
          Height = 36
          Action = CCAccessTokenAction
          Align = alRight
          TabOrder = 3
          WordWrap = True
        end
        object CCActivityIndicator: TActivityIndicator
          AlignWithMargins = True
          Left = 3
          Top = 3
          Align = alLeft
        end
      end
      object Panel9: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 31
        Width = 944
        Height = 22
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel1'
        ShowCaption = False
        TabOrder = 3
        object Label6: TLabel
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 120
          Height = 16
          Align = alLeft
          AutoSize = False
          Caption = 'Realm'
        end
        object CCRealmEdit: TEdit
          Left = 126
          Top = 0
          Width = 818
          Height = 22
          Align = alClient
          TabOrder = 0
          Text = 'iamclient4d'
          ExplicitHeight = 23
        end
      end
      object Panel10: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 59
        Width = 944
        Height = 22
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel1'
        ShowCaption = False
        TabOrder = 4
        object Label7: TLabel
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 120
          Height = 16
          Align = alLeft
          AutoSize = False
          Caption = 'Client'
        end
        object CCClientEdit: TEdit
          Left = 126
          Top = 0
          Width = 818
          Height = 22
          Align = alClient
          TabOrder = 0
          Text = 'demo_private'
          ExplicitHeight = 23
        end
      end
      object Panel11: TPanel
        AlignWithMargins = True
        Left = 3
        Top = 87
        Width = 944
        Height = 22
        Align = alTop
        BevelOuter = bvNone
        Caption = 'Panel1'
        ShowCaption = False
        TabOrder = 5
        object Label8: TLabel
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 120
          Height = 16
          Align = alLeft
          AutoSize = False
          Caption = 'Client secret'
        end
        object CCClientSecretEdit: TEdit
          Left = 126
          Top = 0
          Width = 818
          Height = 22
          Align = alClient
          TabOrder = 0
          Text = 'bdgwQwFXP4x5X2dDv9BkgmKV3cqFe5Or'
          ExplicitHeight = 23
        end
      end
    end
  end
  object ActionList1: TActionList
    Left = 32
    Top = 504
    object LogoutAction: TAction
      Category = 'PKCE'
      Caption = 'Logout'
      OnExecute = LogoutActionExecute
      OnUpdate = LogoutActionUpdate
    end
    object UserInfoAction: TAction
      Category = 'PKCE'
      Caption = 'User info'
      OnExecute = UserInfoActionExecute
      OnUpdate = UserInfoActionUpdate
    end
    object VerifyJWTAction: TAction
      Category = 'PKCE'
      Caption = 'Verify JWT'
      OnExecute = VerifyJWTActionExecute
      OnUpdate = VerifyJWTActionUpdate
    end
    object LoginAction: TAction
      Category = 'PKCE'
      Caption = 'Login'
      OnExecute = LoginActionExecute
      OnUpdate = LoginActionUpdate
    end
    object AccessTokenAsyncAction: TAction
      Category = 'PKCE'
      Caption = 'Access token'
      OnExecute = AccessTokenAsyncActionExecute
      OnUpdate = AccessTokenAsyncActionUpdate
    end
    object LoginCredentialAccess: TAction
      Category = 'Client Credentials'
      Caption = 'Login'
      OnExecute = LoginCredentialAccessExecute
    end
    object ConnectToUserManagerAction: TAction
      Category = 'User Management'
      Caption = 'Connect to user manager'
      OnExecute = ConnectToUserManagerActionExecute
      OnUpdate = ConnectToUserManagerActionUpdate
    end
    object GetUserAction: TAction
      Category = 'User Management Samples'
      Caption = 'Get user by ID'
      OnExecute = GetUserActionExecute
      OnUpdate = GetUserActionUpdate
    end
    object CCLogoutAction: TAction
      Category = 'Client Credentials'
      Caption = 'Logout'
      OnExecute = CCLogoutActionExecute
      OnUpdate = CCLogoutActionUpdate
    end
    object CCAccessTokenAction: TAction
      Category = 'Client Credentials'
      Caption = 'Acess token'
      OnExecute = CCAccessTokenActionExecute
      OnUpdate = CCAccessTokenActionUpdate
    end
    object CCVerifyJWTAction: TAction
      Category = 'Client Credentials'
      Caption = 'Verify JWT'
      OnExecute = CCVerifyJWTActionExecute
      OnUpdate = CCVerifyJWTActionUpdate
    end
    object UserSampleCreateUserAction: TAction
      Category = 'User Management Samples'
      Caption = 'Create sample user'
      OnExecute = UserSampleCreateUserActionExecute
      OnUpdate = UserSampleCreateUserActionUpdate
    end
    object UserByUserNameAction: TAction
      Category = 'User Management Samples'
      Caption = 'Get user by username'
      OnExecute = UserByUserNameActionExecute
      OnUpdate = UserByUserNameActionUpdate
    end
    object UpdateUserAction: TAction
      Category = 'User Management Samples'
      Caption = 'Update user'
      OnExecute = UpdateUserActionExecute
      OnUpdate = UpdateUserActionUpdate
    end
    object DeleteUserAction: TAction
      Category = 'User Management Samples'
      Caption = 'Delete user'
      OnExecute = DeleteUserActionExecute
      OnUpdate = DeleteUserActionUpdate
    end
    object CreateMultipleUsersAction: TAction
      Category = 'User Management Samples'
      Caption = 'Create multiple users'
      OnExecute = CreateMultipleUsersActionExecute
      OnUpdate = CreateMultipleUsersActionUpdate
    end
    object UpdateMultipleUsersAction: TAction
      Category = 'User Management Samples'
      Caption = 'Update multiple users'
      OnExecute = UpdateMultipleUsersActionExecute
      OnUpdate = UpdateMultipleUsersActionUpdate
    end
    object DeleteMultipleUserAction: TAction
      Category = 'User Management Samples'
      Caption = 'Delete multiple user'
      OnExecute = DeleteMultipleUserActionExecute
      OnUpdate = DeleteMultipleUserActionUpdate
    end
    object ChangePasswordsAction: TAction
      Category = 'User Management Samples'
      Caption = 'Reset users passwords'
      OnExecute = ChangePasswordsActionExecute
      OnUpdate = ChangePasswordsActionUpdate
    end
    object AssignRolesUsersAction: TAction
      Category = 'User Management Samples'
      Caption = 'Assign roles to users'
      OnExecute = AssignRolesUsersActionExecute
      OnUpdate = AssignRolesUsersActionUpdate
    end
    object ClientsRealmAction: TAction
      Category = 'User Management Samples'
      Caption = 'Clients and roles'
      OnExecute = ClientsRealmActionExecute
      OnUpdate = ClientsRealmActionUpdate
    end
    object ChangePasswordAction: TAction
      Category = 'User Management Samples'
      Caption = 'Sey temporary password'
      OnExecute = ChangePasswordActionExecute
      OnUpdate = ChangePasswordActionUpdate
    end
    object RealmRoleAction: TAction
      Category = 'User Management Samples'
      Caption = 'Get realms role'
      OnExecute = RealmRoleActionExecute
      OnUpdate = RealmRoleActionUpdate
    end
    object UserRolesAction: TAction
      Category = 'User Management Samples'
      Caption = 'User roles'
      OnExecute = UserRolesActionExecute
      OnUpdate = UserRolesActionUpdate
    end
    object SearchUserAction: TAction
      Category = 'User Management Samples'
      Caption = 'Search user'
      OnExecute = SearchUserActionExecute
      OnUpdate = SearchUserActionUpdate
    end
    object UserFederatedAction: TAction
      Category = 'User Management Samples'
      Caption = 'User federated'
      OnExecute = UserFederatedActionExecute
      OnUpdate = UserFederatedActionUpdate
    end
  end
end
